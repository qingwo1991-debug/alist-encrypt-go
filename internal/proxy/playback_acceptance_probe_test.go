package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/playbacktest"
)

// Exercise real metadata HTTP reads as well as download reads. Cancellation is
// event-triggered, not a one-second probe-budget sleep or a latency percentile.
func TestPlaybackAcceptanceMetadataProbeCancellation(t *testing.T) {
	body, _ := buildV3Container(t, "pw", 64, []byte("metadata-probe-plaintext"))
	for _, stall := range []string{"headers", "body"} {
		t.Run(stall, func(t *testing.T) {
			u := playbacktest.New(body, playbacktest.Behavior{Range: playbacktest.RangeAccept, StallHeaders: stall == "headers", StallBody: stall == "body"}, nil)
			defer u.Close()
			sp := acceptanceProxy(u)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan ContentInspectionResult, 1)
			go func() {
				done <- sp.InspectEncryptedContentResult(ctx, u.URL("/object"), nil, &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}, int64(len(body)))
			}()
			event := u.Started
			if stall == "body" {
				event = u.HeadersSent
			}
			select {
			case <-event:
			case <-ctx.Done():
				t.Fatal("metadata request did not reach fixture")
			}
			cancel()
			select {
			case result := <-done:
				if result.Confirmed {
					t.Fatalf("stalled probe falsely confirmed: %+v", result)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("metadata cancellation did not unblock")
			}
			u.Close()
			snapshot := u.Snapshot()
			if snapshot.RequestCount != 1 || snapshot.BodyBytes != 0 {
				t.Fatalf("probe snapshot=%+v", snapshot)
			}
		})
	}
}
