package config

import (
	"errors"
	"sync"
	"testing"
)

func TestRuntimeRevisionRejectsABAAndFailedUpdate(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	initial := cfg.RuntimeRevision()
	original := cfg.AlistServerSnapshot()
	changed := original
	changed.ServerHost = "changed.example"
	if err := cfg.UpdateAlistServer(changed); err != nil {
		t.Fatal(err)
	}
	if err := cfg.UpdateAlistServer(original); err != nil {
		t.Fatal(err)
	}
	if cfg.RuntimeRevision() != initial+2 {
		t.Fatal("successful updates must advance generation")
	}
	published := false
	ok, err := cfg.PublishIfRevision(initial, func() error { published = true; return nil })
	if err != nil || ok || published {
		t.Fatal("stale ABA generation published")
	}
	invalid := original
	invalid.ServerPort = 0
	if err := cfg.UpdateAlistServer(invalid); err == nil {
		t.Fatal("accepted invalid update")
	}
	if cfg.RuntimeRevision() != initial+2 {
		t.Fatal("failed update advanced generation")
	}
	sentinel := errors.New("publication failed")
	ok, err = cfg.PublishIfRevision(cfg.RuntimeRevision(), func() error { return sentinel })
	if !ok || !errors.Is(err, sentinel) {
		t.Fatalf("publication error lost: %v %v", ok, err)
	}
}

func TestRuntimeRevisionPublicationSerializesUpdate(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	rev := cfg.RuntimeRevision()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok, err := cfg.PublishIfRevision(rev, func() error { close(started); <-release; return nil })
		if !ok || err != nil {
			t.Errorf("publication: %v %v", ok, err)
		}
	}()
	<-started
	server := cfg.AlistServer // Initial fixture is unchanged, no update has started yet.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cfg.UpdateAlistServer(server); err != nil {
			t.Error(err)
		}
		close(done)
	}()
	select {
	case <-done:
		t.Error("update crossed publication read guard")
	default:
	}
	close(release)
	wg.Wait()
	if cfg.RuntimeRevision() != rev+1 {
		t.Fatal("update did not finish")
	}
}
