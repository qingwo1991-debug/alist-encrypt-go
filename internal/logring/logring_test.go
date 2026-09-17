package logring

import (
	"strings"
	"testing"
)

func TestRingKeepsRecentLines(t *testing.T) {
	r := NewRing(3)
	for _, line := range []string{"a\n", "b\n", "c\n", "d\n"} {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	got := r.Tail(100)
	if strings.Join(got, "|") != "b|c|d" {
		t.Fatalf("expected ring to keep newest 3, got %q", strings.Join(got, "|"))
	}
	if r.Len() != 3 {
		t.Fatalf("Len = %d, want 3", r.Len())
	}
}

func TestRingBuffersPartialLine(t *testing.T) {
	r := NewRing(10)
	mustWrite(t, r, "hello")
	mustWrite(t, r, " world\nnext\n")
	got := r.Tail(10)
	if len(got) != 2 || got[0] != "hello world" || got[1] != "next" {
		t.Fatalf("unexpected lines: %q", got)
	}
}

func TestRingStripsANSI(t *testing.T) {
	r := NewRing(10)
	mustWrite(t, r, "\x1b[31mred log\x1b[0m\n")
	got := r.Tail(10)
	if len(got) != 1 || strings.Contains(got[0], "\x1b") {
		t.Fatalf("want clean line, got %q", got)
	}
	if got[0] != "red log" {
		t.Fatalf("want 'red log', got %q", got[0])
	}
}

func TestRingSkippingEmptyLines(t *testing.T) {
	r := NewRing(10)
	mustWrite(t, r, "\nempty-padding\n\n")
	got := r.Tail(10)
	if len(got) != 1 || got[0] != "empty-padding" {
		t.Fatalf("unexpected lines %q", got)
	}
}

func TestRingTailLimit(t *testing.T) {
	r := NewRing(10)
	for i := 0; i < 10; i++ {
		mustWrite(t, r, "x\n")
	}
	if got := r.Tail(3); len(got) != 3 {
		t.Fatalf("Tail(3) = %d, want 3", len(got))
	}
	if got := r.Tail(0); got != nil {
		t.Fatalf("Tail(0) should be nil")
	}
}

func mustWrite(t *testing.T, r *Ring, s string) {
	t.Helper()
	if _, err := r.Write([]byte(s)); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
}
