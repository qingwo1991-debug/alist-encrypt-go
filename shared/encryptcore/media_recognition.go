package encryption

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MediaRecognitionDefaultChunk int64 = 1 << 20
const MediaRecognitionMaximumChunk int64 = 32 << 20

// Independent process cap prevents many instances multiplying record memory.
var mediaRecognitionProcessBytes atomic.Int64

const mediaRecognitionProcessLimit int64 = 64 << 20

// MediaRecognitionConfig is trusted instance configuration, never a request hint.
// LargeRecordOptIn explicitly authorizes the expensive recognize-record0 operation.
type MediaRecognitionConfig struct{ LargeRecordOptIn bool }
type MediaRecognitionResult struct {
	Meta                                                          ContentMeta
	Layout, Ext, MIME, Reason, ETag, LastModified, ValidatorScope string
	Status                                                        int
	BytesRead, RecordBytes                                        int64
	RecordAuthenticated                                           bool
	StrongETag                                                    bool
}

// MediaRecognizer owns admission, bytes and cancellation; Stop joins HTTP/record
// work but never closes the process-owned KDF service. No unknown-revision cache.
type MediaRecognizer struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	stopped         bool
	active, pending int
	leased          int64
	config          MediaRecognitionConfig
}

func NewMediaRecognizer(config MediaRecognitionConfig) *MediaRecognizer {
	ctx, cancel := context.WithCancel(context.Background())
	return &MediaRecognizer{ctx: ctx, cancel: cancel, config: config}
}
func (m *MediaRecognizer) SetConfig(config MediaRecognitionConfig) {
	m.mu.Lock()
	m.config = config
	m.mu.Unlock()
}
func (m *MediaRecognizer) Stop() {
	m.mu.Lock()
	m.stopped = true
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
}
func (m *MediaRecognizer) LeasedBytes() int64 { m.mu.Lock(); defer m.mu.Unlock(); return m.leased }

// RecognizeV3 authenticates exactly one complete record and classifies at most
// 4096 plaintext bytes. Geometry/header/trailer are NOT AEAD authenticated (empty AAD).
func (m *MediaRecognizer) RecognizeV3(ctx context.Context, client *http.Client, target, password string, auth http.Header, observed int64) (out MediaRecognitionResult, err error) {
	fail := func(reason string) (MediaRecognitionResult, error) {
		out.Reason = reason
		return out, fmt.Errorf("media recognition: %s", reason)
	}
	if m == nil || client == nil || ctx == nil || observed < 48 {
		return fail("invalid_input")
	}
	u, parseErr := url.Parse(target)
	if parseErr != nil || u == nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fail("invalid_target")
	}
	m.mu.Lock()
	if m.stopped || m.pending >= 2 {
		m.mu.Unlock()
		return fail("budget_rejected: admission")
	}
	m.pending++
	m.wg.Add(1)
	largeOptIn := m.config.LargeRecordOptIn
	m.mu.Unlock()
	defer m.wg.Done()
	deadline := 5 * time.Second
	if largeOptIn {
		deadline = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	// Bounded pending wait; single active operation per instance.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		if m.active == 0 {
			m.active = 1
			m.pending--
			m.mu.Unlock()
			break
		}
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.pending--
			m.mu.Unlock()
			return fail("cancelled")
		case <-ticker.C:
		}
	}
	defer func() { m.mu.Lock(); m.active = 0; m.mu.Unlock() }()
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var scope, etag, last string
	strongETag := true
	fetch := func(start, end int64) ([]byte, error) {
		current := target
		headers := auth.Clone()
		for hop := 0; hop <= 2; hop++ {
			req, e := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
			if e != nil {
				return nil, e
			}
			for _, key := range []string{"Authorization", "Cookie", "User-Agent"} {
				for _, v := range headers.Values(key) {
					req.Header.Add(key, v)
				}
			}
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			req.Header.Set("Accept-Encoding", "identity")
			resp, e := c.Do(req)
			if e != nil {
				return nil, e
			}
			out.Status = resp.StatusCode
			if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
				location := resp.Header.Get("Location")
				resp.Body.Close()
				u, e := url.Parse(current)
				if e != nil {
					return nil, e
				}
				v, e := url.Parse(location)
				if e != nil || location == "" {
					return nil, fmt.Errorf("invalid redirect")
				}
				next := u.ResolveReference(v)
				if next.Scheme != "http" && next.Scheme != "https" || next.User != nil {
					return nil, fmt.Errorf("invalid redirect")
				}
				if !strings.EqualFold(u.Scheme, next.Scheme) || !strings.EqualFold(u.Host, next.Host) {
					headers = make(http.Header)
				}
				current = next.String()
				continue
			}
			if resp.StatusCode != 200 && resp.StatusCode != 206 {
				resp.Body.Close()
				return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
			}
			if resp.Uncompressed || (resp.Header.Get("Content-Encoding") != "" && !strings.EqualFold(resp.Header.Get("Content-Encoding"), "identity")) {
				resp.Body.Close()
				return nil, fmt.Errorf("encoded representation")
			}
			count := end - start + 1
			if resp.StatusCode == 206 {
				want := fmt.Sprintf("bytes %d-%d/%d", start, end, observed)
				if resp.Header.Get("Content-Range") != want || resp.ContentLength != count {
					resp.Body.Close()
					return nil, fmt.Errorf("range geometry")
				}
			} else if start != 0 || resp.ContentLength != observed {
				resp.Body.Close()
				return nil, fmt.Errorf("ignored range cannot bound tail")
			}
			u, _ := url.Parse(current)
			u.RawQuery = ""
			u.Fragment = ""
			u.User = nil
			s := u.String()
			eTag, validETag := SingleStrongETag(resp.Header)
			strongETag = strongETag && validETag
			l := resp.Header.Get("Last-Modified")
			for _, vary := range resp.Header.Values("Vary") {
				for _, f := range strings.Split(vary, ",") {
					switch strings.ToLower(strings.TrimSpace(f)) {
					case "", "accept-encoding", "authorization", "cookie", "user-agent":
					default:
						resp.Body.Close()
						return nil, fmt.Errorf("unscoped vary")
					}
				}
			}
			if scope != "" && (scope != s || etag != eTag || last != l) {
				resp.Body.Close()
				return nil, fmt.Errorf("representation changed")
			}
			scope, etag, last = s, eTag, l
			b := make([]byte, count)
			n, e := io.ReadFull(resp.Body, b)
			out.BytesRead += int64(n)
			resp.Body.Close()
			if e != nil {
				return nil, e
			}
			return b, nil
		}
		return nil, fmt.Errorf("redirect limit")
	}
	header, e := fetch(0, 47)
	if e != nil {
		return fail("transport: " + e.Error())
	}
	if HasV3Magic(header) {
		out.Meta.Version = ContentVersionV3
	}
	if !HasV3Magic(header) || header[6] != 3 || header[7] != 0 || binary.BigEndian.Uint32(header[36:40]) != 16 || binary.BigEndian.Uint32(header[44:48]) != 0 {
		return fail("invalid_header")
	}
	chunk := int64(binary.BigEndian.Uint32(header[32:36]))
	kdf := binary.BigEndian.Uint32(header[40:44])
	limit := MediaRecognitionDefaultChunk
	if largeOptIn {
		limit = MediaRecognitionMaximumChunk
	}
	if chunk <= 0 || chunk > limit {
		return fail("budget_rejected: record_chunk=" + strconv.FormatInt(chunk, 10))
	}
	if kdf == 0 || kdf > 600000 {
		return fail("budget_rejected: kdf_iterations")
	}
	plain := int64(binary.BigEndian.Uint64(header[24:32]))
	if plain < 0 {
		return fail("invalid_geometry")
	}
	out.Layout = "fixed"
	if plain == 0 {
		tail, e := fetch(observed-16, observed-1)
		if e != nil {
			return fail("transport: " + e.Error())
		}
		if !bytes.Equal(tail[:8], []byte{'V', '3', 'E', '4', 0, 0, 0, 0}) {
			return fail("invalid_trailer")
		}
		plain = int64(binary.BigEndian.Uint64(tail[8:]))
		out.Layout = "trailer"
	}
	bodySize := observed - 48
	if out.Layout == "trailer" {
		bodySize -= 16
	}
	records := plain / chunk
	if plain%chunk != 0 {
		records++
	}
	if plain <= 0 || bodySize < 0 || bodySize%(chunk+16) != 0 || bodySize/(chunk+16) != records || records > 1<<32 {
		return fail("invalid_geometry_or_empty")
	}
	out.Meta = ContentMeta{Version: ContentVersionV3, HeaderLen: 48, PlainSize: plain, CiphertextSize: observed, ChunkSize: uint32(chunk), KDFIterations: kdf, NonceField: append([]byte(nil), header[8:24]...)}
	// One in-place ciphertext/plaintext buffer plus repeated header; lease held
	// through KDF and classification, and released only after real work returns.
	lease := chunk + 16 + 48
	for {
		used := mediaRecognitionProcessBytes.Load()
		if lease > mediaRecognitionProcessLimit-used {
			return fail("budget_rejected: process_bytes")
		}
		if mediaRecognitionProcessBytes.CompareAndSwap(used, used+lease) {
			break
		}
	}
	defer mediaRecognitionProcessBytes.Add(-lease)
	m.mu.Lock()
	m.leased += lease
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.leased -= lease; m.mu.Unlock() }()
	b, e := fetch(0, 48+chunk+16-1)
	if e != nil {
		return fail("transport: " + e.Error())
	}
	if !bytes.Equal(header, b[:48]) {
		return fail("representation_header_changed")
	}
	key, e := DeriveV3KeyContext(ctx, password, out.Meta.NonceField, kdf, V3KDFSpeculative)
	if e != nil {
		return fail("kdf: " + e.Error())
	}
	cipher, e := NewV3ChunkCipher(key, out.Meta.NonceField)
	if e != nil {
		return fail("cipher: " + e.Error())
	}
	record := b[48:]
	p, e := cipher.open(record[:0], 0, record)
	if e != nil {
		return fail("record_authentication_failed")
	}
	out.RecordBytes = int64(len(record))
	out.RecordAuthenticated = true
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	n := int64(4096)
	if plain < n {
		n = plain
	}
	if chunk < n {
		n = chunk
	}
	out.StrongETag = strongETag
	out.Ext, out.MIME, _ = DetectVideoFormat(p[:n])
	out.ETag, out.LastModified, out.ValidatorScope = etag, last, scope
	if out.Ext == "" {
		return fail("unknown_video_signature")
	}
	out.Reason = "record_authenticated_geometry_checked_video_signature"
	return out, nil
}
