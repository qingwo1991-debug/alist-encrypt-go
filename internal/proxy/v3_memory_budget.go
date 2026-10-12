package proxy

import "sync/atomic"

// Bound simultaneously allocated V3 record buffers independently of the HTTP
// stream-count limit. This preserves container compatibility while rejecting a
// pathological chunk before allocating it. Cache/pool memory is separate.
const v3RecordBudgetBytes int64 = 256 << 20

type v3MemoryBudget struct{ used atomic.Int64 }

func (s *StreamProxy) acquireV3Memory(bytes int64) (func(), bool) {
	if bytes <= 0 || bytes > v3RecordBudgetBytes {
		return nil, false
	}
	if s == nil || s.v3Memory == nil {
		return func() {}, true
	}
	budget := s.v3Memory
	for {
		used := budget.used.Load()
		if bytes > v3RecordBudgetBytes-used {
			return nil, false
		}
		if budget.used.CompareAndSwap(used, used+bytes) {
			var done atomic.Bool
			return func() {
				if done.CompareAndSwap(false, true) {
					budget.used.Add(-bytes)
				}
			}, true
		}
	}
}
