package proxy

import (
	"sync"
	"testing"
)

func TestV3MemoryBudgetBoundsAndReleases(t *testing.T) {
	s := &StreamProxy{v3Memory: &v3MemoryBudget{}}
	if _, ok := s.acquireV3Memory(v3RecordBudgetBytes + 1); ok {
		t.Fatal("accepted oversized record")
	}
	release, ok := s.acquireV3Memory(v3RecordBudgetBytes)
	if !ok {
		t.Fatal("failed to acquire empty budget")
	}
	if _, ok := s.acquireV3Memory(1); ok {
		t.Fatal("exceeded byte budget")
	}
	release()
	release()
	if s.v3Memory.used.Load() != 0 {
		t.Fatal("release must be idempotent")
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				release, ok := s.acquireV3Memory(16 << 20)
				if ok {
					if used := s.v3Memory.used.Load(); used > v3RecordBudgetBytes {
						t.Errorf("budget exceeded: %d", used)
					}
					release()
				}
			}
		}()
	}
	wg.Wait()
	if s.v3Memory.used.Load() != 0 {
		t.Fatal("reservation leaked")
	}
}
