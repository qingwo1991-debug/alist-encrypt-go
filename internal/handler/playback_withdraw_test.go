package handler

import (
	"errors"
	"testing"
)

func TestPlaybackInterestClearRetainsGenerationAndExactReferences(t *testing.T) {
	ps := interestTestScheduler(t, 8)
	interestAdvance(t, ps, "one", 1, "/A")
	interestAdvance(t, ps, "two", 1, "/A")
	interestEnqueue(t, ps, "one", 1, "/A", WarmForeground)
	interestEnqueue(t, ps, "two", 1, "/A", WarmForeground)
	task := (<-ps.queue).interest
	if _, err := ps.ClearPlaybackInterest("verified", "sessionone", "provider", 2); err != nil {
		t.Fatal(err)
	}
	if task.ctx.Err() != nil || len(task.refs) != 1 {
		t.Fatal("clear canceled shared owner")
	}
	if _, err := ps.AdvancePlaybackInterest("verified", "sessionone", "provider", 1, "/A"); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal("clear erased monotonic tombstone", err)
	}
	if err := ps.EnqueuePlaybackInterest("verified", "sessionone", "provider", 2, interestTestFile("/A"), nil, 0, WarmSpeculative); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal("cleared generation re-enqueued", err)
	}
	interestAdvance(t, ps, "one", 3, "/B")
	interestEnqueue(t, ps, "one", 3, "/B", WarmForeground)
	newer := (<-ps.queue).interest
	if _, err := ps.ClearPlaybackInterest("verified", "sessionone", "provider", 2); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal(err)
	}
	if newer.ctx.Err() != nil {
		t.Fatal("delayed withdraw erased new launch")
	}
	if _, err := ps.ClearPlaybackInterest("other-scope", "sessiontwo", "provider", 2); err != nil {
		t.Fatal(err)
	}
	if task.ctx.Err() != nil {
		t.Fatal("wrong JWT scope released actual owner")
	}
	if _, err := ps.ClearPlaybackInterest("verified", "sessiontwo", "provider", 2); err != nil {
		t.Fatal(err)
	}
	if task.ctx.Err() == nil {
		t.Fatal("last owner did not cancel")
	}
	ps.finishPlaybackInterest(task)
	ps.finishPlaybackInterest(newer)
}
