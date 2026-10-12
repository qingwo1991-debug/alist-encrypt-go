package encryption

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type v3KDFTestResult struct {
	key []byte
	err error
}

func v3KDFTestCall(s *v3KDFService, ctx context.Context, password string, nonce []byte, priority V3KDFPriority) <-chan v3KDFTestResult {
	out := make(chan v3KDFTestResult, 1)
	go func() { key, err := s.key(ctx, password, nonce, 1, priority, false); out <- v3KDFTestResult{key, err} }()
	return out
}
func v3KDFTestReceive(t *testing.T, ch <-chan v3KDFTestResult) v3KDFTestResult {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("KDF caller did not settle")
		return v3KDFTestResult{}
	}
}
func v3KDFTestWait(t *testing.T, s *v3KDFService, predicate func(V3KDFStats) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		s.mu.Lock()
		changed := s.changed
		stats := s.stats
		stats.Queued = len(s.queue)
		stats.Flights = len(s.flights)
		s.mu.Unlock()
		if predicate(stats) {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("KDF stats timeout %+v", stats)
		}
	}
}
func TestV3KDFAdmissionBoundedAndSameKeyJoin(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 1, waiters: 3}, func(string, []byte, uint32) []byte { calls.Add(1); <-release; return bytes.Repeat([]byte{7}, 32) })
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	a := v3KDFTestCall(s, context.Background(), "A", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Active == 1 })
	b := v3KDFTestCall(s, context.Background(), "B", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	if _, err := s.key(context.Background(), "C", nonce, 1, V3KDFForeground, false); !errors.Is(err, ErrV3KDFBusy) {
		t.Fatal("queue overflow accepted")
	}
	join := v3KDFTestCall(s, context.Background(), "A", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Waiters == 3 })
	if _, err := s.key(context.Background(), "A", nonce, 1, V3KDFForeground, false); !errors.Is(err, ErrV3KDFBusy) {
		t.Fatal("waiter overflow accepted")
	}
	release <- struct{}{}
	if r := v3KDFTestReceive(t, a); r.err != nil {
		t.Fatal(r.err)
	}
	if r := v3KDFTestReceive(t, join); r.err != nil {
		t.Fatal(r.err)
	}
	release <- struct{}{}
	if r := v3KDFTestReceive(t, b); r.err != nil {
		t.Fatal(r.err)
	}
	if calls.Load() != 2 {
		t.Fatalf("same-key duplicated derivation %d", calls.Load())
	}
	st := s.snapshot()
	if st.Active != 0 || st.Waiters != 0 || st.Flights != 0 || st.Queued != 0 || st.Started != 2 || st.Completed != 2 || st.Refused != 2 {
		t.Fatalf("conservation %+v", st)
	}
}
func TestV3KDFCanceledWaiterDoesNotCancelSharedLeader(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 2, waiters: 8}, func(string, []byte, uint32) []byte { calls.Add(1); <-release; return bytes.Repeat([]byte{8}, 32) })
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	ctx, cancel := context.WithCancel(context.Background())
	a := v3KDFTestCall(s, ctx, "shared", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Active == 1 })
	b := v3KDFTestCall(s, context.Background(), "shared", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Waiters == 2 })
	cancel()
	if r := v3KDFTestReceive(t, a); !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	if st := s.snapshot(); st.Active != 1 || st.Waiters != 1 || st.Flights != 1 {
		t.Fatalf("leader canceled %+v", st)
	}
	release <- struct{}{}
	r := v3KDFTestReceive(t, b)
	if r.err != nil || len(r.key) != 32 || calls.Load() != 1 {
		t.Fatalf("shared result %+v", r)
	}
}
func TestV3KDFAllRunningWaitersCancelKeepsFlightAndNonceSnapshot(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	var calls atomic.Int32
	original := []byte(fmt.Sprintf("%s/%d", t.Name(), time.Now().UnixNano()))
	want := append([]byte(nil), original...)
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 2, waiters: 8}, func(_ string, salt []byte, _ uint32) []byte {
		calls.Add(1)
		close(entered)
		<-release
		if !bytes.Equal(salt, want) {
			t.Error("worker retained mutable caller nonce")
		}
		return bytes.Repeat([]byte{9}, 32)
	})
	defer s.shutdown()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	a := v3KDFTestCall(s, ctx, "orphan", original, V3KDFForeground)
	<-entered
	cancel()
	if r := v3KDFTestReceive(t, a); !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	for i := range original {
		original[i] ^= 0xff
	}
	if st := s.snapshot(); st.Active != 1 || st.Waiters != 0 || st.Flights != 1 || st.OrphanRunning != 1 {
		t.Fatalf("orphan forgotten %+v", st)
	}
	b := v3KDFTestCall(s, context.Background(), "orphan", want, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Waiters == 1 })
	release <- struct{}{}
	if r := v3KDFTestReceive(t, b); r.err != nil {
		t.Fatal(r.err)
	}
	if calls.Load() != 1 {
		t.Fatal("orphan restarted CPU")
	}
}
func TestV3KDFQueuedWithdrawalAndForegroundPromotion(t *testing.T) {
	release := make(chan struct{})
	started := make(chan string, 8)
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 4, waiters: 8}, func(password string, _ []byte, _ uint32) []byte {
		started <- password
		<-release
		return bytes.Repeat([]byte{10}, 32)
	})
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	active := v3KDFTestCall(s, context.Background(), "active", nonce, V3KDFForeground)
	if <-started != "active" {
		t.Fatal("wrong active")
	}
	ctx, cancel := context.WithCancel(context.Background())
	removed := v3KDFTestCall(s, ctx, "removed", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	cancel()
	if r := v3KDFTestReceive(t, removed); !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	low := v3KDFTestCall(s, context.Background(), "low", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	promoted := v3KDFTestCall(s, context.Background(), "promoted", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 2 })
	fg := v3KDFTestCall(s, context.Background(), "promoted", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Promoted == 1 })
	release <- struct{}{}
	if r := v3KDFTestReceive(t, active); r.err != nil {
		t.Fatal(r.err)
	}
	if password := <-started; password != "promoted" {
		t.Fatalf("promotion ordering %s", password)
	}
	release <- struct{}{}
	v3KDFTestReceive(t, promoted)
	v3KDFTestReceive(t, fg)
	if password := <-started; password != "low" {
		t.Fatalf("withdrawn task ran %s", password)
	}
	release <- struct{}{}
	v3KDFTestReceive(t, low)
	if st := s.snapshot(); st.Started != 3 || st.CanceledQueued != 1 || st.Waiters != 0 {
		t.Fatalf("withdrawal conservation %+v", st)
	}
}
func TestV3KDFForegroundReservedSlot(t *testing.T) {
	release := make(chan struct{})
	foregroundRelease := make(chan struct{})
	started := make(chan string, 4)
	s := newV3KDFService(v3KDFLimits{active: 2, queue: 4, waiters: 8}, func(password string, _ []byte, _ uint32) []byte {
		started <- password
		if password == "foreground" {
			<-foregroundRelease
		} else {
			<-release
		}
		return bytes.Repeat([]byte{11}, 32)
	})
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	low1 := v3KDFTestCall(s, context.Background(), "low1", nonce, V3KDFSpeculative)
	<-started
	low2 := v3KDFTestCall(s, context.Background(), "low2", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	if st := s.snapshot(); st.Active != 1 || st.SpeculativeActive != 1 {
		t.Fatalf("speculative reserve %+v", st)
	}
	foreground := v3KDFTestCall(s, context.Background(), "foreground", nonce, V3KDFForeground)
	if p := <-started; p != "foreground" {
		t.Fatalf("reserve lost %s", p)
	}
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Active == 2 })
	// Separate barriers prevent a newly started speculative worker from stealing
	// a completion token intended for the foreground worker.
	close(foregroundRelease)
	v3KDFTestReceive(t, foreground)
	release <- struct{}{}
	v3KDFTestReceive(t, low1)
	if p := <-started; p != "low2" {
		t.Fatal(p)
	}
	release <- struct{}{}
	v3KDFTestReceive(t, low2)
}
func TestV3KDFNormalizationCacheCopiesAndCanceledHit(t *testing.T) {
	var calls atomic.Int32
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 1, waiters: 2}, func(_ string, _ []byte, iterations uint32) []byte {
		calls.Add(1)
		if iterations != 600000 {
			t.Error("iterations not normalized")
		}
		return bytes.Repeat([]byte{12}, 32)
	})
	defer s.shutdown()
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	first, err := s.key(context.Background(), "password", nonce, 0, V3KDFForeground, false)
	if err != nil {
		t.Fatal(err)
	}
	first[0]++
	second, err := s.key(context.Background(), "password", nonce, 600000, V3KDFSpeculative, false)
	if err != nil || calls.Load() != 1 || second[0] != 12 {
		t.Fatal("cache copy/normalization failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.key(ctx, "password", nonce, 0, V3KDFForeground, false); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled cache hit returned key")
	}
}
func TestV3KDFShutdownDrainsActualCPUAndClosesQueue(t *testing.T) {
	release := make(chan struct{})
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 2, waiters: 4}, func(string, []byte, uint32) []byte { <-release; return bytes.Repeat([]byte{13}, 32) })
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	a := v3KDFTestCall(s, context.Background(), "active", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Active == 1 })
	b := v3KDFTestCall(s, context.Background(), "queued", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	stopped := make(chan struct{})
	go func() { s.shutdown(); close(stopped) }()
	if r := v3KDFTestReceive(t, b); !errors.Is(r.err, ErrV3KDFClosed) {
		t.Fatal(r.err)
	}
	select {
	case <-stopped:
		t.Fatal("shutdown faked CPU completion")
	default:
	}
	if s.snapshot().Active != 1 {
		t.Fatal("running slot released early")
	}
	close(release)
	v3KDFTestReceive(t, a)
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not join")
	}
	if st := s.snapshot(); st.Active != 0 || st.Queued != 0 || st.Flights != 0 || st.Waiters != 0 {
		t.Fatalf("shutdown leak %+v", st)
	}
	if _, err := s.key(context.Background(), "new", nonce, 1, V3KDFForeground, false); !errors.Is(err, ErrV3KDFClosed) {
		t.Fatal("closed admission accepted")
	}
}
func TestV3KDFLegacyWaitsForAdmissionWithoutRegistryExpansion(t *testing.T) {
	release := make(chan struct{})
	s := newV3KDFService(v3KDFLimits{active: 1, queue: 1, waiters: 1}, func(string, []byte, uint32) []byte { <-release; return bytes.Repeat([]byte{14}, 32) })
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	a := v3KDFTestCall(s, context.Background(), "active", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Active == 1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan v3KDFTestResult, 1)
	go func() {
		key, err := s.key(ctx, "legacy", nonce, 1, V3KDFForeground, true)
		result <- v3KDFTestResult{key, err}
	}()
	// Canceling a legacy admission wait is test-only; production compatibility
	// callers use Background and retain their historical synchronous semantics.
	cancel()
	if r := v3KDFTestReceive(t, result); !errors.Is(r.err, context.Canceled) {
		t.Fatal(r.err)
	}
	if st := s.snapshot(); st.Waiters != 1 || st.Flights != 1 || st.Queued != 0 {
		t.Fatalf("legacy registry expansion %+v", st)
	}
	release <- struct{}{}
	v3KDFTestReceive(t, a)
}

func TestV3KDFForegroundQueueAdmissionReserved(t *testing.T) {
	release := make(chan struct{})
	started := make(chan string, 4)
	s := newV3KDFService(v3KDFLimits{active: 2, queue: 2, waiters: 8}, func(password string, _ []byte, _ uint32) []byte {
		started <- password
		<-release
		return bytes.Repeat([]byte{15}, 32)
	})
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	low1 := v3KDFTestCall(s, context.Background(), "low1", nonce, V3KDFSpeculative)
	<-started
	low2 := v3KDFTestCall(s, context.Background(), "low2", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	if _, err := s.key(context.Background(), "low3", nonce, 1, V3KDFSpeculative, false); !errors.Is(err, ErrV3KDFBusy) {
		t.Fatal("speculative consumed foreground queue reservation")
	}
	foreground := v3KDFTestCall(s, context.Background(), "foreground", nonce, V3KDFForeground)
	select {
	case name := <-started:
		if name != "foreground" {
			t.Fatal(name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("foreground admission blocked behind speculative queue")
	}
	if st := s.snapshot(); st.Active != 2 || st.Queued != 1 || st.Waiters != 3 {
		t.Fatalf("reserved admission %+v", st)
	}
	// Send one token per execution, including the queued speculative record.
	release <- struct{}{}
	release <- struct{}{}
	release <- struct{}{}
	v3KDFTestReceive(t, low1)
	v3KDFTestReceive(t, low2)
	v3KDFTestReceive(t, foreground)
}

func TestV3KDFForegroundWaiterAdmissionReserved(t *testing.T) {
	release := make(chan struct{})
	s := newV3KDFService(v3KDFLimits{active: 2, queue: 3, waiters: 3}, func(string, []byte, uint32) []byte { <-release; return bytes.Repeat([]byte{16}, 32) })
	defer s.shutdown()
	defer close(release)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	first := v3KDFTestCall(s, context.Background(), "shared", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Active == 1 })
	second := v3KDFTestCall(s, context.Background(), "shared", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Waiters == 2 })
	if _, err := s.key(context.Background(), "shared", nonce, 1, V3KDFSpeculative, false); !errors.Is(err, ErrV3KDFBusy) {
		t.Fatal("speculative fanout consumed final waiter")
	}
	foreground := v3KDFTestCall(s, context.Background(), "shared", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Waiters == 3 })
	release <- struct{}{}
	v3KDFTestReceive(t, first)
	v3KDFTestReceive(t, second)
	v3KDFTestReceive(t, foreground)
}

func TestV3KDFCanceledForegroundPromotionDemotesQueuedInterest(t *testing.T) {
	activeRelease := make(chan struct{})
	specRelease := make(chan struct{})
	fgRelease := make(chan struct{})
	started := make(chan string, 8)
	s := newV3KDFService(v3KDFLimits{active: 2, queue: 4, waiters: 8}, func(password string, _ []byte, _ uint32) []byte {
		started <- password
		switch password {
		case "active1", "active2":
			<-activeRelease
		case "foreground":
			<-fgRelease
		default:
			<-specRelease
		}
		return bytes.Repeat([]byte{17}, 32)
	})
	defer s.shutdown()
	defer close(specRelease)
	defer close(fgRelease)
	nonce := []byte(fmt.Sprintf("%s/%p", t.Name(), s))
	a1 := v3KDFTestCall(s, context.Background(), "active1", nonce, V3KDFForeground)
	<-started
	a2 := v3KDFTestCall(s, context.Background(), "active2", nonce, V3KDFForeground)
	<-started
	low1 := v3KDFTestCall(s, context.Background(), "low1", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 1 })
	low2 := v3KDFTestCall(s, context.Background(), "low2", nonce, V3KDFSpeculative)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Queued == 2 })
	ctx, cancel := context.WithCancel(context.Background())
	promoter := v3KDFTestCall(s, ctx, "low1", nonce, V3KDFForeground)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.Promoted == 1 })
	cancel()
	if result := v3KDFTestReceive(t, promoter); !errors.Is(result.err, context.Canceled) {
		t.Fatal(result.err)
	}
	s.mu.Lock()
	queued := s.flights[v3KeyCacheKey("low1", nonce, 1)]
	demoted := queued != nil && queued.priority == V3KDFSpeculative && queued.foregroundWaiters == 0
	s.mu.Unlock()
	if !demoted {
		t.Fatal("queued priority retained departed foreground interest")
	}
	close(activeRelease)
	v3KDFTestReceive(t, a1)
	v3KDFTestReceive(t, a2)
	v3KDFTestWait(t, s, func(st V3KDFStats) bool { return st.SpeculativeActive == 1 && st.Queued == 1 })
	<-started
	foreground := v3KDFTestCall(s, context.Background(), "foreground", nonce, V3KDFForeground)
	select {
	case name := <-started:
		if name != "foreground" {
			t.Fatalf("speculative took reserved slot: %s", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("foreground reserve blocked")
	}
	if st := s.snapshot(); st.Active != 2 || st.SpeculativeActive != 1 {
		t.Fatalf("execution classification %+v", st)
	}
	fgRelease <- struct{}{}
	v3KDFTestReceive(t, foreground)
	specRelease <- struct{}{}
	<-started
	specRelease <- struct{}{}
	v3KDFTestReceive(t, low1)
	v3KDFTestReceive(t, low2)
}
