package handler

import (
	"errors"
	"testing"
)

func TestPlaybackInterestClearRetainsGenerationAndExactReferences(t *testing.T) {
	ps := interestTestScheduler(t, 8)
	interestAdvance(t, ps, "one", 7, "/A")
	interestAdvance(t, ps, "two", 7, "/A")
	interestEnqueue(t, ps, "one", 7, "/A", WarmForeground)
	interestEnqueue(t, ps, "two", 7, "/A", WarmForeground)
	task := (<-ps.queue).interest
	for i := 0; i < 2; i++ {
		if advanced, err := ps.ClearPlaybackInterest("verified", "sessionone", "provider", 7); err != nil || advanced {
			t.Fatal("same generation clear/retry", advanced, err)
		}
	}
	if task.ctx.Err() != nil || len(task.refs) != 1 {
		t.Fatal("clear canceled shared owner")
	}
	if _, err := ps.AdvancePlaybackInterest("verified", "sessionone", "provider", 7, "/A"); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal("cleared generation resurrected", err)
	}
	if err := ps.EnqueuePlaybackInterest("verified", "sessionone", "provider", 7, interestTestFile("/A"), nil, 0, WarmSpeculative); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal("cleared generation re-enqueued", err)
	}
	interestAdvance(t, ps, "one", 8, "/B")
	interestEnqueue(t, ps, "one", 8, "/B", WarmForeground)
	newer := (<-ps.queue).interest
	for _, generation := range []uint64{6, 7} {
		if _, err := ps.ClearPlaybackInterest("verified", "sessionone", "provider", generation); !errors.Is(err, ErrPlaybackInterestStale) {
			t.Fatal(err)
		}
	}
	if newer.ctx.Err() != nil {
		t.Fatal("delayed withdraw erased new launch")
	}
	if _, err := ps.ClearPlaybackInterest("other-scope", "sessiontwo", "provider", 7); err != nil {
		t.Fatal(err)
	}
	if task.ctx.Err() != nil {
		t.Fatal("wrong JWT scope released actual owner")
	}
	if _, err := ps.ClearPlaybackInterest("verified", "sessiontwo", "provider", 7); err != nil {
		t.Fatal(err)
	}
	if task.ctx.Err() == nil {
		t.Fatal("last owner did not cancel")
	}
	// Preserve compatibility with existing next-generation clear clients.
	if advanced, err := ps.ClearPlaybackInterest("verified", "sessionone", "provider", 9); err != nil || !advanced {
		t.Fatal(advanced, err)
	}
	if newer.ctx.Err() == nil {
		t.Fatal("higher generation clear did not cancel")
	}
	ps.finishPlaybackInterest(task)
	ps.finishPlaybackInterest(newer)
}
