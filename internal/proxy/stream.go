package proxy

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/config"
)

// Buffer pool for streaming - default 512KB buffers for high-bitrate video
var streamBufferSize int64 = 512 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		size := atomic.LoadInt64(&streamBufferSize)
		buf := make([]byte, size)
		return &buf
	},
}

func clampStreamBufferKB(kb int) int {
	if kb < 32 {
		return 32
	}
	if kb > 4096 {
		return 4096
	}
	return kb
}

func applyStreamBufferConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	alist := cfg.AlistServerSnapshot()
	if alist.StreamBufferKb <= 0 {
		return
	}
	effectiveKB := clampStreamBufferKB(alist.StreamBufferKb)
	newSize := int64(effectiveKB * 1024)
	atomic.StoreInt64(&streamBufferSize, newSize)
	// No need to replace bufferPool — the pool's New func already reads
	// atomic.LoadInt64(&streamBufferSize), so new allocations automatically
	// pick up the updated size. Old buffers remain valid until recycled.
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// GetBuffer exports buffer pool for other packages
func GetBuffer() *[]byte {
	return getBuffer()
}

// PutBuffer exports buffer pool for other packages
func PutBuffer(buf *[]byte) {
	putBuffer(buf)
}

// StreamProxy handles streaming proxy with encryption/decryption
type StreamProxy struct {
	client           *Client
	cfg              *config.Config
	compatStore      RangeCompatStore
	redirectRewriter RedirectRewriter
	rangeStats       *rangeLearningStats
	playbackHintsMu  sync.RWMutex
	playbackHints    map[string]recentPlaybackHint
	playbackHintHits uint64
	chunkedHintHits  uint64
	rangeHintHits    uint64
	fullHintHits     uint64
	cbGate           *backoff.Gate           // circuit breaker for the configured upstream and invalid targets
	cbGates          *circuitBreakerRegistry // host-isolated circuit breakers for CDN/data-plane targets
	retrier          *backoff.Retrier        // retry with jitter for transient network errors
	uploadMetaMu     sync.Mutex
	uploadMeta       map[string]uploadMetaEntry
	blockCache       *decryptedBlockCache
	streamLimiter    chan struct{}
	activeStreams    int64
	rejectedStreams  uint64
}

// StreamOutcome describes the streaming result for strategy selection.
type StreamOutcome struct {
	Err             error
	Retryable       bool
	FailureReason   string
	NoLearning      bool
	BytesWritten    int64
	ExpectedBytes   int64
	ResponseStarted bool
	StatusCode      int
	ContentType     string
	ETag            string
}

// NewStreamProxy creates a new stream proxy
func NewStreamProxy(cfg *config.Config) *StreamProxy {
	applyStreamBufferConfig(cfg)
	cbThreshold := 5
	cbCooldown := 30 * time.Second
	maxActiveStreams := 32
	retrier := backoff.DefaultRetrier()
	if cfg != nil {
		alist := cfg.AlistServerSnapshot()
		if alist.CircuitBreakerThreshold > 0 {
			cbThreshold = alist.CircuitBreakerThreshold
		}
		if alist.CircuitBreakerCooldownSecs > 0 {
			cbCooldown = time.Duration(alist.CircuitBreakerCooldownSecs) * time.Second
		}
		if alist.RetryMaxAttempts >= 0 {
			retrier.MaxRetries = alist.RetryMaxAttempts
		}
		if alist.MaxActiveStreams > 0 {
			maxActiveStreams = alist.MaxActiveStreams
		}
	}
	cbGate := backoff.NewGate(cbThreshold, cbCooldown)
	fallbackURL := ""
	if cfg != nil {
		fallbackURL = cfg.GetAlistURL()
	}
	return &StreamProxy{
		client:        NewClient(cfg),
		cfg:           cfg,
		compatStore:   NewMemoryRangeCompatStore(),
		rangeStats:    newRangeLearningStats(),
		playbackHints: make(map[string]recentPlaybackHint),
		cbGate:        cbGate,
		cbGates:       newCircuitBreakerRegistry(cbGate, fallbackURL, cbThreshold, cbCooldown),
		retrier:       retrier,
		uploadMeta:    make(map[string]uploadMetaEntry),
		blockCache:    newDecryptedBlockCacheFromConfig(cfg),
		streamLimiter: make(chan struct{}, maxActiveStreams),
	}
}

// AcquireStream reserves capacity for a decrypt playback stream. It returns a
// release function when accepted, or false when the service is overloaded.
func (s *StreamProxy) AcquireStream() (func(), bool) {
	if s == nil || s.streamLimiter == nil {
		return func() {}, true
	}
	select {
	case s.streamLimiter <- struct{}{}:
		atomic.AddInt64(&s.activeStreams, 1)
		var released atomic.Bool
		return func() {
			if released.Swap(true) {
				return
			}
			<-s.streamLimiter
			atomic.AddInt64(&s.activeStreams, -1)
		}, true
	default:
		atomic.AddUint64(&s.rejectedStreams, 1)
		return nil, false
	}
}

// StreamLimitStats returns current decrypt playback concurrency stats.
func (s *StreamProxy) StreamLimitStats() map[string]interface{} {
	limit := 0
	if s != nil && s.streamLimiter != nil {
		limit = cap(s.streamLimiter)
	}
	var active int64
	var rejected uint64
	if s != nil {
		active = atomic.LoadInt64(&s.activeStreams)
		rejected = atomic.LoadUint64(&s.rejectedStreams)
	}
	return map[string]interface{}{
		"active_streams":   active,
		"max_active":       limit,
		"rejected_streams": rejected,
	}
}

func newDecryptedBlockCacheFromConfig(cfg *config.Config) *decryptedBlockCache {
	if cfg == nil {
		return nil
	}
	alist := cfg.AlistServerSnapshot()
	if !alist.EnableDecryptedBlockCache {
		return nil
	}
	cacheMB := alist.DecryptedBlockCacheMb
	if cacheMB <= 0 {
		cacheMB = 128
	}
	if cacheMB < 16 {
		cacheMB = 16
	}
	if cacheMB > 2048 {
		cacheMB = 2048
	}
	blockKB := alist.DecryptedBlockSizeKb
	if blockKB <= 0 {
		blockKB = 256
	}
	if blockKB < 32 {
		blockKB = 32
	}
	if blockKB > 4096 {
		blockKB = 4096
	}
	return newDecryptedBlockCache(int64(cacheMB)*1024*1024, int64(blockKB)*1024)
}

// SetRedirectRewriter registers a redirect rewriter for decrypt streams.
func (s *StreamProxy) SetRedirectRewriter(rewriter RedirectRewriter) {
	s.redirectRewriter = rewriter
}
