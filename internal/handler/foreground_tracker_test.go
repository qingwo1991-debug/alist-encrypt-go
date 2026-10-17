package handler

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestForegroundTrackerNestedAndIdempotentRelease(t *testing.T) {
	f := NewForegroundTracker(func() bool { return true })
	first, second := f.Begin(), f.Begin()
	first()
	first()
	if busy, _ := f.state(); !busy {
		t.Fatal("nested foreground released early")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.WaitBackground(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	second()
	if err := f.WaitBackground(context.Background()); err != nil {
		t.Fatal(err)
	}
	if busy, _ := f.state(); busy {
		t.Fatal("foreground leaked")
	}
}

func TestForegroundTrackerStandardIsNoop(t *testing.T) {
	f := NewForegroundTracker(func() bool { return false })
	defer f.Begin()()
	if busy, _ := f.state(); busy {
		t.Fatal("standard paused background")
	}
	if err := f.WaitBackground(context.Background()); err != nil {
		t.Fatal(err)
	}
	var absent *ForegroundTracker
	absent.Begin()()
	if err := absent.WaitBackground(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestForegroundGatePausesDispatchButNotExplicitForeground(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	// Queue before switching to trusted mode, as with an in-process profile change.
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "scan.mp4"), nil, 4096, probeSourceStartupScan)
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "foreground.mp4"), nil, 4096, probeSourceFirstFrame)
	f := NewForegroundTracker(func() bool { return true })
	ps.SetForegroundTracker(f)
	done := f.Begin()
	item, sem, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/foreground.mp4" {
		t.Fatalf("foreground blocked: %+v", item)
	}
	ps.releaseProviderSlot(sem)
	ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
	// No additional bulk work should even reserve queue/cooldown state.
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "bulk.mp4"), nil, 4096, probeSourceFSList)
	if got := ps.Stats()["queue_len"]; got != 1 {
		t.Fatalf("bulk admitted: queue=%v", got)
	}
	done()
	item, sem, ok = ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/scan.mp4" {
		t.Fatal("background failed to resume")
	}
	ps.releaseProviderSlot(sem)
	ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
}

func TestProbeDelayDoesNotClaimProviderOrBlockReadyItem(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	delayed := fairDispatchFile("ready.example", "delayed.mp4")
	ready := fairDispatchFile("ready.example", "ready.mp4")
	ps.queue <- probeItem{file: delayed, notBefore: time.Now().Add(time.Hour)}
	ps.queue <- probeItem{file: ready}
	item, sem, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != ready.DisplayPath {
		t.Fatalf("delayed item blocked ready provider: %+v", item)
	}
	if len(sem) != 1 {
		t.Fatal("provider admission not bounded")
	}
	ps.releaseProviderSlot(sem)
	if len(sem) != 0 {
		t.Fatal("provider slot leaked")
	}
}
