package backoff

import (
	"errors"
	"testing"
	"time"
)

func TestGateAllow(t *testing.T) {
	g := NewGate(3, 100*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !g.Allow() {
			t.Fatalf("should allow before threshold, attempt %d", i)
		}
		g.RecordFailure()
	}

	if g.Allow() {
		t.Fatal("should block after 3 failures")
	}
}

func TestGateCooldown(t *testing.T) {
	g := NewGate(2, 50*time.Millisecond)

	g.RecordFailure()
	g.RecordFailure()
	if g.Allow() {
		t.Fatal("should block after 2 failures")
	}

	time.Sleep(60 * time.Millisecond)
	if !g.Allow() {
		t.Fatal("should allow after cooldown")
	}
}

func TestGateRecordSuccessResets(t *testing.T) {
	g := NewGate(3, time.Hour)

	g.RecordFailure()
	g.RecordFailure()
	g.RecordSuccess()

	if !g.Allow() {
		t.Fatal("success should reset failure count")
	}

	g.RecordFailure()
	g.RecordFailure()
	if !g.Allow() {
		t.Fatal("should not block after only 2 failures after reset")
	}
}

func TestGateState(t *testing.T) {
	g := NewGate(2, 100*time.Millisecond)

	open, failCount, rem := g.State()
	if open || failCount != 0 || rem != 0 {
		t.Fatalf("initial state: open=%v count=%d rem=%v", open, failCount, rem)
	}

	g.RecordFailure()
	g.RecordFailure()

	open, failCount, rem = g.State()
	if !open {
		t.Fatal("should be open after 2 failures")
	}
	if rem <= 0 {
		t.Fatalf("should have remaining time, got %v", rem)
	}
}

func TestRetrierSuccessFirstTry(t *testing.T) {
	r := DefaultRetrier()
	calls := 0
	err := r.Do(t.Context(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("should call once on success, got %d", calls)
	}
}

func TestRetrierRetriesTransient(t *testing.T) {
	r := DefaultRetrier()
	r.Max = 1 * time.Millisecond // speed up
	r.Initial = 1 * time.Millisecond

	calls := 0
	err := r.Do(t.Context(), func() error {
		calls++
		if calls < 3 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("should retry 2 times (3 total), got %d calls", calls)
	}
}

func TestRetrierFailsFastOnPermanent(t *testing.T) {
	r := DefaultRetrier()

	calls := 0
	err := r.Do(t.Context(), func() error {
		calls++
		return errors.New("invalid parameter")
	})
	if err == nil {
		t.Fatal("should return error")
	}
	if calls != 1 {
		t.Fatalf("should NOT retry permanent error, got %d calls", calls)
	}
}

func TestRetrierExhaustsRetries(t *testing.T) {
	r := DefaultRetrier()
	r.Max = 1 * time.Millisecond
	r.Initial = 1 * time.Millisecond
	r.MaxRetries = 2

	calls := 0
	err := r.Do(t.Context(), func() error {
		calls++
		return errors.New("connection reset by peer")
	})
	if err == nil {
		t.Fatal("should return error after exhausting retries")
	}
	if calls != 3 { // 1 initial + 2 retries
		t.Fatalf("should call 3 times, got %d", calls)
	}
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		err      error
		transient bool
	}{
		{errors.New("dial tcp: connection refused"), true},
		{errors.New("read tcp: connection reset by peer"), true},
		{errors.New("write tcp: broken pipe"), true},
		{errors.New("dial tcp: no such host"), true},
		{errors.New("dial tcp: no route to host"), true},
		{errors.New("network is unreachable"), true},
		{errors.New("i/o timeout"), true},
		{errors.New("context deadline exceeded"), true},
		{errors.New("tls: handshake timeout"), true},
		{errors.New("invalid parameter"), false},
		{errors.New("file not found"), false},
		{nil, false},
	}
	for _, tt := range tests {
		if IsTransient(tt.err) != tt.transient {
			t.Errorf("IsTransient(%q) = %v, want %v", tt.err, IsTransient(tt.err), tt.transient)
		}
	}
}

func TestIsTransientStatus(t *testing.T) {
	tests := []struct {
		code      int
		transient bool
	}{
		{500, true}, {502, true}, {503, true}, {504, true},
		{429, true}, {408, true},
		{200, false}, {301, false}, {400, false}, {401, false},
		{404, false},
	}
	for _, tt := range tests {
		if IsTransientStatus(tt.code) != tt.transient {
			t.Errorf("IsTransientStatus(%d) = %v, want %v", tt.code, IsTransientStatus(tt.code), tt.transient)
		}
	}
}
