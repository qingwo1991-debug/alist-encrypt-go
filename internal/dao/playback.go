package dao

import (
	"context"
	"errors"
	"github.com/rs/zerolog/log"
	"sync"
	"time"
)

// playbackState belongs to FileDAO. Invalidation fences durable publication;
// canceled loads retain admission until the actual worker exits. Stop joins IO.
type playbackState struct {
	mu             sync.Mutex
	epoch          uint64
	pathFence      map[string]*playbackPathFence
	flights        map[string]*playbackFlight
	confirmed      map[string]FileInfo
	stopped        bool
	durableBlocked bool // A failed invalidation must not resurrect durable confirmations.
	wg             sync.WaitGroup
}

// playbackPathFence revokes confirmation for one display path without touching
// any other object. revokedAt additionally rejects a durable record written
// before the revocation, which a by-identity delete cannot reach.
type playbackPathFence struct {
	epoch     uint64
	revokedAt time.Time
}

// playbackPathFenceLimit bounds the per-path fence. Dropping an entry would let
// a stale publication match its previous value, so overflow degrades to the
// global fence instead of silently forgetting a revocation.
const playbackPathFenceLimit = 8192

type playbackFlight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	value   interface{}
	err     error
}

// PlaybackEpoch returns the fence a caller must present to publish a
// confirmation for path. Both counters only ever increase and a value is only
// ever compared against another value for the same path, so the sum is a sound
// equality fence: it moves on global invalidation (config change, restart,
// overflow) and on revocation of that one path.
func (d *FileDAO) PlaybackEpoch(path string) uint64 {
	d.playback.mu.Lock()
	defer d.playback.mu.Unlock()
	return d.playbackEpochLocked(path)
}

func (d *FileDAO) playbackEpochLocked(path string) uint64 {
	epoch := d.playback.epoch
	if fence := d.playback.pathFence[path]; fence != nil {
		epoch += fence.epoch
	}
	return epoch
}
func (d *FileDAO) GetConfirmedPlayback(identity string) (*FileInfo, bool) {
	s := &d.playback
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, false
	}
	info, ok := s.confirmed[identity]
	if !ok && d.store != nil && !s.durableBlocked {
		if d.store.GetPlayback(identity, &info) == nil {
			ok = info.GeometryIdentity == identity
		}
	}
	age := time.Since(info.GeometryConfirmedAt)
	if !ok || info.GeometryIdentity != identity || info.GeometryConfirmedAt.IsZero() || age < 0 || age >= 24*time.Hour {
		return nil, false
	}
	// A durable record survives a revocation that could not find it by identity.
	if fence := s.pathFence[info.Path]; fence != nil && info.GeometryConfirmedAt.Before(fence.revokedAt) {
		return nil, false
	}
	if s.confirmed == nil {
		s.confirmed = make(map[string]FileInfo)
	}
	if len(s.confirmed) >= 2048 {
		for key := range s.confirmed {
			delete(s.confirmed, key)
			break
		}
	}
	s.confirmed[identity] = info
	info.NonceField = append([]byte(nil), info.NonceField...)
	return &info, true
}
func (d *FileDAO) PublishConfirmedPlayback(info *FileInfo, epoch uint64) bool {
	s := &d.playback
	s.mu.Lock()
	defer s.mu.Unlock()
	if info == nil || info.GeometryIdentity == "" || s.stopped || d.playbackEpochLocked(info.Path) != epoch {
		return false
	}
	copy := *info
	copy.NonceField = append([]byte(nil), info.NonceField...)
	if d.store != nil && !s.durableBlocked {
		if err := d.store.SetPlayback(copy.GeometryIdentity, &copy); err != nil {
			return false
		}
	}
	if s.confirmed == nil {
		s.confirmed = make(map[string]FileInfo)
	}
	if len(s.confirmed) >= 2048 {
		for k := range s.confirmed {
			delete(s.confirmed, k)
			break
		}
	}
	s.confirmed[copy.GeometryIdentity] = copy
	// Legacy consumers still see the same complete geometry. Dedicated Bolt
	// confirmation above, rather than optional MySQL write-behind, owns restart.
	_ = d.Set(&copy)
	return true
}
func (d *FileDAO) PublishPlaybackInfo(info *FileInfo, epoch uint64) bool {
	s := &d.playback
	s.mu.Lock()
	defer s.mu.Unlock()
	if info == nil || s.stopped || d.playbackEpochLocked(info.Path) != epoch {
		return false
	}
	return d.Set(info) == nil
}
func (d *FileDAO) DoPlaybackLoad(ctx context.Context, key string, load func(context.Context) (interface{}, error)) (interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &d.playback
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil, errors.New("playback cache stopped")
	}
	if s.flights == nil {
		s.flights = make(map[string]*playbackFlight)
	}
	f := s.flights[key]
	if f == nil {
		if len(s.flights) >= 128 {
			s.mu.Unlock()
			return nil, errors.New("playback cache admission busy")
		}
		work, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		f = &playbackFlight{done: make(chan struct{}), cancel: cancel}
		s.flights[key] = f
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer cancel()
			value, err := load(work)
			s.mu.Lock()
			f.value, f.err = value, err
			delete(s.flights, key)
			close(f.done)
			s.mu.Unlock()
		}()
	}
	f.waiters++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		f.waiters--
		if f.waiters == 0 {
			f.cancel()
		}
		s.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return f.value, f.err
	}
}

// invalidateDisplayPathLocked revokes confirmation for a single display path.
// Every other object keeps its proof: one listing entry whose size moved must
// not discard the confirmations of every unrelated container, and must not move
// the fence that queued background probes were admitted under.
func (d *FileDAO) invalidateDisplayPathLocked(displayPath string) {
	s := &d.playback
	if s.pathFence == nil {
		s.pathFence = make(map[string]*playbackPathFence)
	}
	if len(s.pathFence) >= playbackPathFenceLimit {
		// Bounded memory: forgetting a revocation would let a stale publication
		// match its previous epoch, so degrade to the global fence instead.
		d.invalidatePlaybackLocked()
		return
	}
	fence := s.pathFence[displayPath]
	if fence == nil {
		fence = &playbackPathFence{}
		s.pathFence[displayPath] = fence
	}
	fence.epoch++
	fence.revokedAt = time.Now()
	for identity, info := range s.confirmed {
		if info.Path != displayPath {
			continue
		}
		delete(s.confirmed, identity)
		if d.store != nil && !s.durableBlocked {
			if err := d.store.DeletePlayback(identity); err != nil {
				s.durableBlocked = true
				log.Error().Err(err).Msg("playback durable invalidation failed; persisted confirmation reads disabled until successful invalidation; repair storage before restarting")
			}
		}
	}
}

func (d *FileDAO) invalidatePlaybackLocked() {
	d.playback.epoch++
	d.playback.confirmed = nil
	if d.store != nil {
		if err := d.store.ClearPlayback(); err != nil {
			d.playback.durableBlocked = true
			log.Error().Err(err).Msg("playback durable invalidation failed; persisted confirmation reads disabled until successful invalidation; repair storage before restarting")
		} else {
			d.playback.durableBlocked = false
		}
	}
	for _, f := range d.playback.flights {
		f.cancel()
	}
}
func (d *FileDAO) stopPlayback() {
	s := &d.playback
	s.mu.Lock()
	s.stopped = true
	for _, f := range s.flights {
		f.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
