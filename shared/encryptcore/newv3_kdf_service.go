package encryption

import (
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// V3KDFPriority is dispatch priority, not CPU preemption. A running PBKDF2
// cannot be canceled; canceling a caller only withdraws that caller's interest.
type V3KDFPriority uint8

const (
	V3KDFForeground V3KDFPriority = iota
	V3KDFSpeculative
)

var (
	ErrV3KDFBusy   = errors.New("v3: KDF admission busy")
	ErrV3KDFClosed = errors.New("v3: KDF service closed")
)

type V3KDFStats struct {
	Active, Queued, Waiters, Flights, SpeculativeActive                                int
	Started, Completed, Refused, CanceledQueued, CanceledWait, OrphanRunning, Promoted uint64
}
type v3KDFLimits struct{ active, queue, waiters int }
type v3KDFDeriver func(string, []byte, uint32) []byte
type v3KDFFlight struct {
	key, password     string
	nonce             []byte
	iterations        uint32
	priority          V3KDFPriority
	waiters           int
	foregroundWaiters int
	running, finished bool
	done              chan struct{}
	result            []byte
	err               error
}
type v3KDFService struct {
	mu      sync.Mutex
	cond    *sync.Cond
	changed chan struct{}
	limits  v3KDFLimits
	flights map[string]*v3KDFFlight
	queue   []*v3KDFFlight
	stats   V3KDFStats
	derive  v3KDFDeriver
	closed  bool
	workers sync.WaitGroup
}

func deriveV3PBKDF2(password string, nonce []byte, iterations uint32) []byte {
	return pbkdf2.Key([]byte(password), nonce, int(iterations), 32, sha256.New)
}
func newV3KDFService(limits v3KDFLimits, derive v3KDFDeriver) *v3KDFService {
	if limits.active < 1 {
		limits.active = 1
	}
	if limits.queue < 1 {
		limits.queue = 1
	}
	if limits.waiters < 1 {
		limits.waiters = 1
	}
	if derive == nil {
		derive = deriveV3PBKDF2
	}
	s := &v3KDFService{limits: limits, derive: derive, changed: make(chan struct{}), flights: make(map[string]*v3KDFFlight)}
	s.cond = sync.NewCond(&s.mu)
	for i := 0; i < limits.active; i++ {
		s.workers.Add(1)
		go s.worker()
	}
	return s
}
func (s *v3KDFService) notify() {
	close(s.changed)
	s.changed = make(chan struct{})
	s.cond.Broadcast()
}
func (s *v3KDFService) removeQueued(f *v3KDFFlight) {
	for i, q := range s.queue {
		if q == f {
			copy(s.queue[i:], s.queue[i+1:])
			s.queue[len(s.queue)-1] = nil
			s.queue = s.queue[:len(s.queue)-1]
			return
		}
	}
}
func (s *v3KDFService) next() *v3KDFFlight {
	for _, f := range s.queue {
		if f.priority == V3KDFForeground {
			s.removeQueued(f)
			return f
		}
	}
	// With one CPU slot a reserve is physically impossible. Speculative work
	// may run only when no foreground work is queued. With >=2 slots it cannot
	// occupy the final foreground-reserved slot.
	specLimit := s.limits.active - 1
	if specLimit < 1 {
		specLimit = 1
	}
	if s.stats.SpeculativeActive >= specLimit {
		return nil
	}
	if len(s.queue) > 0 {
		f := s.queue[0]
		s.removeQueued(f)
		return f
	}
	return nil
}
func (s *v3KDFService) worker() {
	defer s.workers.Done()
	for {
		s.mu.Lock()
		var f *v3KDFFlight
		for !s.closed {
			f = s.next()
			if f != nil {
				break
			}
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return
		}
		f.running = true
		s.stats.Active++
		s.stats.Started++
		if f.priority == V3KDFSpeculative {
			s.stats.SpeculativeActive++
		}
		s.notify()
		s.mu.Unlock()
		// Service-owned execution: no HTTP context or first waiter owns this work.
		// This fixed worker remains occupied even after every running waiter leaves.
		result := s.derive(f.password, f.nonce, f.iterations)
		storeCachedV3Key(f.key, result, time.Now())
		s.mu.Lock()
		f.result = append([]byte(nil), result...)
		f.password = ""
		clear(f.nonce)
		f.nonce = nil
		f.finished = true
		delete(s.flights, f.key)
		s.stats.Active--
		s.stats.Completed++
		if f.priority == V3KDFSpeculative {
			s.stats.SpeculativeActive--
		}
		close(f.done)
		s.notify()
		s.mu.Unlock()
	}
}
func (s *v3KDFService) detach(f *v3KDFFlight, canceled bool, priority V3KDFPriority) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.waiters--
	if priority == V3KDFForeground {
		f.foregroundWaiters--
	}
	// Priority follows current queued interests, not historical promotion.
	// Running execution classification is immutable until actual completion.
	if !f.running && !f.finished && f.waiters > 0 && f.foregroundWaiters == 0 {
		f.priority = V3KDFSpeculative
	}
	s.stats.Waiters--
	if canceled {
		s.stats.CanceledWait++
	}
	if f.waiters == 0 && !f.finished {
		if !f.running {
			s.removeQueued(f)
			delete(s.flights, f.key)
			f.password = ""
			clear(f.nonce)
			f.nonce = nil
			f.finished = true
			f.err = context.Canceled
			close(f.done)
			s.stats.CanceledQueued++
		} else if canceled {
			s.stats.OrphanRunning++
		}
	}
	s.notify()
}
func (s *v3KDFService) key(ctx context.Context, password string, nonce []byte, iterations uint32, priority V3KDFPriority, legacy bool) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("v3: nil KDF context")
	}
	if priority != V3KDFForeground && priority != V3KDFSpeculative {
		return nil, errors.New("v3: invalid KDF priority")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if iterations == 0 {
		iterations = 600000
	}
	// Snapshot before hashing and before joining; a canceled waiter never leaves
	// its caller-owned salt backing referenced by a still-running worker.
	salt := append([]byte(nil), nonce...)
	cacheKey := v3KeyCacheKey(password, salt, iterations)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if key, hit := loadCachedV3Key(cacheKey, time.Now()); hit {
			return key, nil
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, ErrV3KDFClosed
		}
		// Cache may have filled while waiting for the registry mutex.
		if key, hit := loadCachedV3Key(cacheKey, time.Now()); hit {
			s.mu.Unlock()
			return key, nil
		}
		f := s.flights[cacheKey]
		queueLimit, waiterLimit := s.limits.queue, s.limits.waiters
		if priority == V3KDFSpeculative {
			// Reserve admission as well as execution: a speculative queue or
			// same-key fan-out must not consume the final foreground slot.
			// This conservative total-count rule needs no per-waiter priority
			// ownership: cancellation/promotion keep identical accounting.
			// Test-only limits of one leave no speculative admission capacity;
			// production limits (32/128) allow 31 queued/127 total waiters.
			queueLimit--
			waiterLimit--
		}
		busy := s.stats.Waiters >= waiterLimit || (f == nil && len(s.queue) >= queueLimit)
		if busy {
			if !legacy {
				s.stats.Refused++
				s.mu.Unlock()
				return nil, ErrV3KDFBusy
			}
			changed := s.changed
			s.mu.Unlock()
			// Legacy callers wait synchronously outside admission accounting. No extra
			// service goroutines, flights or waiter channels are allocated for them.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		if f == nil {
			f = &v3KDFFlight{key: cacheKey, password: password, nonce: salt, iterations: iterations, priority: priority, done: make(chan struct{})}
			s.flights[cacheKey] = f
			s.queue = append(s.queue, f)
		} else if !f.running && f.priority == V3KDFSpeculative && priority == V3KDFForeground {
			f.priority = V3KDFForeground
			s.stats.Promoted++
		}
		f.waiters++
		if priority == V3KDFForeground {
			f.foregroundWaiters++
		}
		s.stats.Waiters++
		s.notify()
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			s.detach(f, true, priority)
			return nil, ctx.Err()
		case <-f.done:
			// Prefer canceled caller semantics even when completion races cancellation.
			if err := ctx.Err(); err != nil {
				s.detach(f, true, priority)
				return nil, err
			}
			s.mu.Lock()
			result := append([]byte(nil), f.result...)
			err := f.err
			s.mu.Unlock()
			s.detach(f, false, priority)
			return result, err
		}
	}
}
func (s *v3KDFService) snapshot() V3KDFStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.stats
	stats.Queued = len(s.queue)
	stats.Flights = len(s.flights)
	return stats
}

// shutdown cancels queued work and joins fixed workers. Running PBKDF2 is not
// interruptible; shutdown must wait for its actual completion, never fake slots.
func (s *v3KDFService) shutdown() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		for _, f := range s.queue {
			delete(s.flights, f.key)
			f.password = ""
			clear(f.nonce)
			f.nonce = nil
			f.err = ErrV3KDFClosed
			f.finished = true
			close(f.done)
		}
		s.queue = nil
		s.notify()
	}
	s.mu.Unlock()
	s.workers.Wait()
}

var defaultV3KDFOnce sync.Once
var defaultV3KDF *v3KDFService

func v3DefaultKDFService() *v3KDFService {
	defaultV3KDFOnce.Do(func() {
		active := runtime.GOMAXPROCS(0)
		if active > 2 {
			active = 2
		}
		defaultV3KDF = newV3KDFService(v3KDFLimits{active: active, queue: 32, waiters: 128}, nil)
	})
	return defaultV3KDF
}

// DeriveV3KeyContext derives with bounded global admission and cancellable wait.
// Same-key running work survives waiter cancellation and remains registered.
func DeriveV3KeyContext(ctx context.Context, password string, nonce []byte, iterations uint32, priority V3KDFPriority) ([]byte, error) {
	return v3DefaultKDFService().key(ctx, password, nonce, iterations, priority, false)
}
func V3KDFServiceStats() V3KDFStats { return v3DefaultKDFService().snapshot() }
