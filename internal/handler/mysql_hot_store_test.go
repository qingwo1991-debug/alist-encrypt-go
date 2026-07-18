package handler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type fakeMySQLStrategyPersistence struct {
	mu sync.Mutex

	getCalls    int
	legacyCalls int
	upsertCalls int

	getFn    func(context.Context, string) (*mysqlstore.StrategyRecord, bool, error)
	legacyFn func(context.Context, string) (*mysqlstore.StrategyRecord, bool, error)
	upsertFn func(context.Context, mysqlstore.StrategyRecord) error
}

func (f *fakeMySQLStrategyPersistence) GetStrategy(ctx context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
	f.mu.Lock()
	f.getCalls++
	fn := f.getFn
	f.mu.Unlock()
	if fn == nil {
		return nil, false, nil
	}
	return fn(ctx, provider)
}

func (f *fakeMySQLStrategyPersistence) GetLatestStrategyByProvider(ctx context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
	f.mu.Lock()
	f.legacyCalls++
	fn := f.legacyFn
	f.mu.Unlock()
	if fn == nil {
		return nil, false, nil
	}
	return fn(ctx, provider)
}

func (f *fakeMySQLStrategyPersistence) UpsertStrategy(ctx context.Context, record mysqlstore.StrategyRecord) error {
	f.mu.Lock()
	f.upsertCalls++
	fn := f.upsertFn
	f.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, record)
}

func (f *fakeMySQLStrategyPersistence) calls() (get, legacy, upsert int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCalls, f.legacyCalls, f.upsertCalls
}

func strategyRecord(provider string, preferred proxy.StreamStrategy) *mysqlstore.StrategyRecord {
	return &mysqlstore.StrategyRecord{
		ProviderHost:  provider,
		Preferred:     string(preferred),
		FailuresJSON:  `{"range":2}`,
		SuccessStreak: 3,
		UpdatedAt:     time.Now(),
	}
}

func TestMySQLStrategyStoreCachesPositiveAndNegativeReads(t *testing.T) {
	foundBackend := &fakeMySQLStrategyPersistence{
		getFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			return strategyRecord(provider, proxy.StreamStrategyChunked), true, nil
		},
	}
	foundStore := newMySQLStrategyStore(foundBackend)
	for range 2 {
		state, ok := foundStore.Get("media.example")
		if !ok || state.Preferred != proxy.StreamStrategyChunked {
			t.Fatalf("unexpected cached strategy: ok=%v state=%+v", ok, state)
		}
	}
	get, legacy, _ := foundBackend.calls()
	if get != 1 || legacy != 0 {
		t.Fatalf("positive cache queried persistence more than once: get=%d legacy=%d", get, legacy)
	}

	missingBackend := &fakeMySQLStrategyPersistence{}
	missingStore := newMySQLStrategyStore(missingBackend)
	for range 2 {
		if state, ok := missingStore.Get("missing.example"); ok || state != nil {
			t.Fatalf("unexpected missing strategy: ok=%v state=%+v", ok, state)
		}
	}
	get, legacy, _ = missingBackend.calls()
	if get != 1 || legacy != 1 {
		t.Fatalf("negative cache did not suppress repeated queries: get=%d legacy=%d", get, legacy)
	}
}

func TestMySQLStrategyStoreCoalescesConcurrentMisses(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			once.Do(func() { close(entered) })
			<-release
			return strategyRecord(provider, proxy.StreamStrategyRange), true, nil
		},
	}
	store := newMySQLStrategyStore(backend)

	const workers = 32
	start := make(chan struct{})
	results := make(chan bool, workers)
	for range workers {
		go func() {
			<-start
			_, ok := store.Get("concurrent.example")
			results <- ok
		}()
	}
	close(start)
	<-entered
	close(release)
	for range workers {
		if !<-results {
			t.Fatal("concurrent cache load unexpectedly missed")
		}
	}
	get, _, _ := backend.calls()
	if get != 1 {
		t.Fatalf("singleflight persistence calls=%d, want 1", get)
	}
}

func TestMySQLStrategyStoreReadTimeoutReturnsQuickly(t *testing.T) {
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(ctx context.Context, _ string) (*mysqlstore.StrategyRecord, bool, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("strategy query context has no deadline")
			}
			<-ctx.Done()
			return nil, false, ctx.Err()
		},
	}
	store := newMySQLStrategyStore(backend)
	store.queryTimeout = 20 * time.Millisecond

	started := time.Now()
	if state, ok := store.Get("slow.example"); !ok || state == nil || state.Preferred != "" {
		t.Fatalf("timed-out query did not return placeholder: ok=%v state=%+v", ok, state)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("timed-out strategy read took too long: %v", elapsed)
	}
	if state, ok := store.Get("slow.example"); !ok || state == nil || state.Preferred != "" {
		t.Fatalf("failure cache did not return placeholder: ok=%v state=%+v", ok, state)
	}
	get, _, _ := backend.calls()
	if get != 1 {
		t.Fatalf("strategy failure cache persistence calls=%d, want 1", get)
	}
}

func TestMySQLStrategyStoreTransientFailureDoesNotPersistSelectorDefault(t *testing.T) {
	transientErr := errors.New("mysql temporarily unavailable")
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(context.Context, string) (*mysqlstore.StrategyRecord, bool, error) {
			return nil, false, transientErr
		},
	}
	store := newMySQLStrategyStore(backend)
	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }
	selector, err := NewStrategySelector(nil, store)
	if err != nil {
		t.Fatalf("NewStrategySelector: %v", err)
	}

	for range 2 {
		selected := selector.Select("failure.example")
		if len(selected) != 1 || selected[0] != proxy.StreamStrategyRange {
			t.Fatalf("selector default after transient failure=%v", selected)
		}
	}
	get, legacy, upserts := backend.calls()
	if get != 1 || legacy != 0 || upserts != 0 {
		t.Fatalf("transient Select touched persistence: get=%d legacy=%d upsert=%d", get, legacy, upserts)
	}

	now = now.Add(store.failureTTL + time.Nanosecond)
	selected := selector.Select("failure.example")
	if len(selected) != 1 || selected[0] != proxy.StreamStrategyRange {
		t.Fatalf("selector default after retry=%v", selected)
	}
	get, _, upserts = backend.calls()
	if get != 2 || upserts != 0 {
		t.Fatalf("failure TTL did not retry safely: get=%d upsert=%d", get, upserts)
	}

	selector.RecordSuccess("failure.example", proxy.StreamStrategyRange)
	_, _, upserts = backend.calls()
	if upserts != 1 {
		t.Fatalf("real strategy update after placeholder was not persisted: upserts=%d", upserts)
	}
}

func TestMySQLStrategyStoreTimeoutDoesNotPersistSelectorDefault(t *testing.T) {
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(ctx context.Context, _ string) (*mysqlstore.StrategyRecord, bool, error) {
			<-ctx.Done()
			return nil, false, ctx.Err()
		},
	}
	store := newMySQLStrategyStore(backend)
	store.queryTimeout = 10 * time.Millisecond
	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }
	selector, err := NewStrategySelector(nil, store)
	if err != nil {
		t.Fatalf("NewStrategySelector: %v", err)
	}

	selected := selector.Select("timeout.example")
	if len(selected) != 1 || selected[0] != proxy.StreamStrategyRange {
		t.Fatalf("selector default after timeout=%v", selected)
	}
	get, _, upserts := backend.calls()
	if get != 1 || upserts != 0 {
		t.Fatalf("timed-out Select touched persistence: get=%d upsert=%d", get, upserts)
	}

	now = now.Add(store.failureTTL + time.Nanosecond)
	selector.Select("timeout.example")
	get, _, upserts = backend.calls()
	if get != 2 || upserts != 0 {
		t.Fatalf("timeout TTL did not retry safely: get=%d upsert=%d", get, upserts)
	}
}

func TestMySQLStrategyStoreReusesExpiredLearnedStateOnTransientFailure(t *testing.T) {
	fail := false
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			if fail {
				return nil, false, errors.New("mysql temporarily unavailable")
			}
			return strategyRecord(provider, proxy.StreamStrategyFull), true, nil
		},
	}
	store := newMySQLStrategyStore(backend)
	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }

	learned, ok := store.Get("stale.example")
	if !ok || learned.Preferred != proxy.StreamStrategyFull {
		t.Fatalf("initial learned strategy: ok=%v state=%+v", ok, learned)
	}
	fail = true
	now = now.Add(store.positiveTTL + time.Nanosecond)
	stale, ok := store.Get("stale.example")
	if !ok || stale.Preferred != proxy.StreamStrategyFull {
		t.Fatalf("transient failure did not reuse stale learned state: ok=%v state=%+v", ok, stale)
	}
	get, _, upserts := backend.calls()
	if get != 2 || upserts != 0 {
		t.Fatalf("stale fallback persistence calls: get=%d upsert=%d", get, upserts)
	}
	if again, ok := store.Get("stale.example"); !ok || again.Preferred != proxy.StreamStrategyFull {
		t.Fatalf("stale failure-TTL cache: ok=%v state=%+v", ok, again)
	}
	get, _, _ = backend.calls()
	if get != 2 {
		t.Fatalf("stale failure TTL did not suppress query: get=%d", get)
	}
}

func TestMySQLStrategyStoreLegacyLookupAndWriteThrough(t *testing.T) {
	backend := &fakeMySQLStrategyPersistence{
		legacyFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			record := strategyRecord(provider, proxy.StreamStrategyFull)
			record.OriginalPath = "/legacy/movie.mkv"
			return record, true, nil
		},
	}
	store := newMySQLStrategyStore(backend)
	legacy, ok := store.Get("legacy.example::/ignored")
	if !ok || legacy.Preferred != proxy.StreamStrategyFull {
		t.Fatalf("legacy provider strategy not loaded: ok=%v state=%+v", ok, legacy)
	}
	get, legacyCalls, _ := backend.calls()
	if get != 1 || legacyCalls != 1 {
		t.Fatalf("legacy lookup counts: direct=%d legacy=%d", get, legacyCalls)
	}

	written := &ProviderStrategyState{
		Provider:            "legacy.example",
		Preferred:           proxy.StreamStrategyChunked,
		Failures:            map[proxy.StreamStrategy]int{proxy.StreamStrategyRange: 4},
		CapabilityFailCount: 4,
		LastValidatedAt:     time.Now(),
	}
	if err := store.Set("legacy.example", written); err != nil {
		t.Fatalf("Set: %v", err)
	}
	after, ok := store.Get("legacy.example")
	if !ok || after.Preferred != written.Preferred || after.CapabilityFailCount != written.CapabilityFailCount {
		t.Fatalf("write-through cache returned stale state: ok=%v state=%+v", ok, after)
	}
	if after.Failures[proxy.StreamStrategyRange] != 4 {
		t.Fatalf("write-through failures=%v", after.Failures)
	}
	getAfter, legacyAfter, upserts := backend.calls()
	if getAfter != get || legacyAfter != legacyCalls || upserts != 1 {
		t.Fatalf("read after write hit persistence: get=%d legacy=%d upsert=%d", getAfter, legacyAfter, upserts)
	}
}

func TestMySQLStrategyStoreCacheIsBounded(t *testing.T) {
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			return strategyRecord(provider, proxy.StreamStrategyRange), true, nil
		},
	}
	store := newMySQLStrategyStore(backend)
	store.maxEntries = 2
	for _, provider := range []string{"one.example", "two.example", "three.example"} {
		if _, ok := store.Get(provider); !ok {
			t.Fatalf("Get(%q) missed", provider)
		}
	}
	store.mu.RLock()
	entries := len(store.cache)
	store.mu.RUnlock()
	if entries != 2 {
		t.Fatalf("bounded strategy cache entries=%d, want 2", entries)
	}
}

func TestMySQLStrategyStoreLoadCannotOverwriteConcurrentSet(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			close(entered)
			<-release
			return strategyRecord(provider, proxy.StreamStrategyRange), true, nil
		},
	}
	store := newMySQLStrategyStore(backend)
	loaded := make(chan *ProviderStrategyState, 1)
	go func() {
		state, _ := store.Get("race.example")
		loaded <- state
	}()
	<-entered

	written := &ProviderStrategyState{
		Provider:            "race.example",
		Preferred:           proxy.StreamStrategyFull,
		Failures:            map[proxy.StreamStrategy]int{},
		CapabilityFailCount: 7,
	}
	if err := store.Set("race.example", written); err != nil {
		t.Fatalf("Set: %v", err)
	}
	close(release)
	if state := <-loaded; state == nil || state.Preferred != proxy.StreamStrategyFull || state.CapabilityFailCount != 7 {
		t.Fatalf("in-flight load returned stale DB state: %+v", state)
	}
	after, ok := store.Get("race.example")
	if !ok || after.Preferred != proxy.StreamStrategyFull || after.CapabilityFailCount != 7 {
		t.Fatalf("in-flight load overwrote Set: ok=%v state=%+v", ok, after)
	}
}

func TestMySQLStrategyStoreRetriesDirtyWriteAfterPersistenceError(t *testing.T) {
	persistErr := errors.New("temporary persistence failure")
	attempts := 0
	backend := &fakeMySQLStrategyPersistence{
		upsertFn: func(context.Context, mysqlstore.StrategyRecord) error {
			attempts++
			if attempts == 1 {
				return persistErr
			}
			return nil
		},
	}
	store := newMySQLStrategyStore(backend)
	state := &ProviderStrategyState{
		Provider:  "dirty.example",
		Preferred: proxy.StreamStrategyChunked,
		Failures:  map[proxy.StreamStrategy]int{},
	}
	if err := store.Set("dirty.example", state); !errors.Is(err, persistErr) {
		t.Fatalf("first Set error=%v, want %v", err, persistErr)
	}
	if cached, ok := store.Get("dirty.example"); !ok || cached.Preferred != state.Preferred {
		t.Fatalf("failed write was not retained for read-through: ok=%v state=%+v", ok, cached)
	}
	if err := store.Set("dirty.example", state); err != nil {
		t.Fatalf("retry Set: %v", err)
	}
	if err := store.Set("dirty.example", state); err != nil {
		t.Fatalf("persisted duplicate Set: %v", err)
	}
	_, _, upserts := backend.calls()
	if upserts != 2 {
		t.Fatalf("strategy persistence attempts=%d, want 2", upserts)
	}
}

func TestMySQLStrategyStoreGenerationSurvivesWriteCacheEviction(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := &fakeMySQLStrategyPersistence{
		getFn: func(_ context.Context, provider string) (*mysqlstore.StrategyRecord, bool, error) {
			if provider == "race-evict.example" {
				close(entered)
				<-release
				return strategyRecord(provider, proxy.StreamStrategyRange), true, nil
			}
			return strategyRecord(provider, proxy.StreamStrategyChunked), true, nil
		},
	}
	store := newMySQLStrategyStore(backend)
	store.maxEntries = 1
	type result struct {
		state *ProviderStrategyState
		ok    bool
	}
	loaded := make(chan result, 1)
	go func() {
		state, ok := store.Get("race-evict.example")
		loaded <- result{state: state, ok: ok}
	}()
	<-entered

	written := &ProviderStrategyState{
		Provider:            "race-evict.example",
		Preferred:           proxy.StreamStrategyFull,
		Failures:            map[proxy.StreamStrategy]int{},
		CapabilityFailCount: 8,
	}
	if err := store.Set("race-evict.example", written); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok := store.Get("evictor.example"); !ok {
		t.Fatal("evictor strategy was not loaded")
	}
	close(release)

	resultAfterEviction := <-loaded
	if resultAfterEviction.ok || resultAfterEviction.state != nil {
		t.Fatalf("stale load escaped after write cache eviction: %+v", resultAfterEviction)
	}
	store.mu.RLock()
	_, staleCached := store.cache["race-evict.example"]
	store.mu.RUnlock()
	if staleCached {
		t.Fatal("stale strategy load repopulated the evicted write")
	}
}

type fakeMySQLRangeCompatPersistence struct {
	mu sync.Mutex

	getCalls    int
	upsertCalls int
	countCalls  int

	getFn    func(context.Context, string, string) (*mysqlstore.RangeCompatRecord, bool, error)
	upsertFn func(context.Context, mysqlstore.RangeCompatRecord) error
}

func (f *fakeMySQLRangeCompatPersistence) GetRangeCompat(ctx context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
	f.mu.Lock()
	f.getCalls++
	fn := f.getFn
	f.mu.Unlock()
	if fn == nil {
		return nil, false, nil
	}
	return fn(ctx, providerHost, storageKey)
}

func (f *fakeMySQLRangeCompatPersistence) UpsertRangeCompat(ctx context.Context, record mysqlstore.RangeCompatRecord) error {
	f.mu.Lock()
	f.upsertCalls++
	fn := f.upsertFn
	f.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, record)
}

func (f *fakeMySQLRangeCompatPersistence) CountRangeCompatActive(context.Context) (int64, error) {
	f.mu.Lock()
	f.countCalls++
	f.mu.Unlock()
	return 0, nil
}

func (f *fakeMySQLRangeCompatPersistence) calls() (get, upsert int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCalls, f.upsertCalls
}

func rangeCompatRecord(providerHost, storageKey string) *mysqlstore.RangeCompatRecord {
	return &mysqlstore.RangeCompatRecord{
		ProviderHost:        providerHost,
		StorageKey:          storageKey,
		Incompatible:        true,
		ConsecutiveFailures: 3,
		LastReason:          "range_unsupported",
		UpdatedAt:           time.Now(),
	}
}

func TestMySQLRangeCompatStoreCachesPositiveAndNegativeReads(t *testing.T) {
	foundBackend := &fakeMySQLRangeCompatPersistence{
		getFn: func(_ context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
			return rangeCompatRecord(providerHost, storageKey), true, nil
		},
	}
	foundStore := newMySQLRangeCompatStore(foundBackend)
	for range 2 {
		state, ok, err := foundStore.Get("media.example::/movie.mkv")
		if err != nil || !ok || !state.Incompatible {
			t.Fatalf("unexpected cached range state: ok=%v state=%+v err=%v", ok, state, err)
		}
	}
	get, _ := foundBackend.calls()
	if get != 1 {
		t.Fatalf("positive range cache persistence calls=%d, want 1", get)
	}

	missingBackend := &fakeMySQLRangeCompatPersistence{}
	missingStore := newMySQLRangeCompatStore(missingBackend)
	for range 2 {
		if state, ok, err := missingStore.Get("missing.example::/movie.mkv"); err != nil || ok {
			t.Fatalf("unexpected missing range state: ok=%v state=%+v err=%v", ok, state, err)
		}
	}
	get, _ = missingBackend.calls()
	if get != 1 {
		t.Fatalf("negative range cache persistence calls=%d, want 1", get)
	}
}

func TestMySQLRangeCompatStorePreservesIPv6Provider(t *testing.T) {
	const provider = "[2001:db8::1]:8443"
	backend := &fakeMySQLRangeCompatPersistence{
		getFn: func(_ context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
			if providerHost != provider || storageKey != "/movie.mkv" {
				t.Fatalf("persistence key=(%q,%q), want (%q,%q)", providerHost, storageKey, provider, "/movie.mkv")
			}
			return rangeCompatRecord(providerHost, storageKey), true, nil
		},
	}
	store := newMySQLRangeCompatStore(backend)
	if _, ok, err := store.Get(provider + "::/movie.mkv"); err != nil || !ok {
		t.Fatalf("IPv6 range state: ok=%v err=%v", ok, err)
	}
}

func TestMySQLRangeCompatStoreCoalescesConcurrentMisses(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	backend := &fakeMySQLRangeCompatPersistence{
		getFn: func(_ context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
			once.Do(func() { close(entered) })
			<-release
			return rangeCompatRecord(providerHost, storageKey), true, nil
		},
	}
	store := newMySQLRangeCompatStore(backend)

	const workers = 32
	start := make(chan struct{})
	results := make(chan error, workers)
	for range workers {
		go func() {
			<-start
			_, ok, err := store.Get("concurrent.example::/movie.mkv")
			if err == nil && !ok {
				err = errors.New("range state not found")
			}
			results <- err
		}()
	}
	close(start)
	<-entered
	close(release)
	for range workers {
		if err := <-results; err != nil {
			t.Fatalf("concurrent range load: %v", err)
		}
	}
	get, _ := backend.calls()
	if get != 1 {
		t.Fatalf("range singleflight persistence calls=%d, want 1", get)
	}
}

func TestMySQLRangeCompatStoreTimeoutAndWriteThrough(t *testing.T) {
	backend := &fakeMySQLRangeCompatPersistence{
		getFn: func(ctx context.Context, _, _ string) (*mysqlstore.RangeCompatRecord, bool, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("range query context has no deadline")
			}
			<-ctx.Done()
			return nil, false, ctx.Err()
		},
	}
	store := newMySQLRangeCompatStore(backend)
	store.queryTimeout = 20 * time.Millisecond

	started := time.Now()
	_, ok, err := store.Get("slow.example::/movie.mkv")
	if ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow range query: ok=%v err=%v", ok, err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("timed-out range read took too long: %v", elapsed)
	}
	if state, cached, cachedErr := store.Get("slow.example::/movie.mkv"); cachedErr != nil || cached {
		t.Fatalf("range failure cache returned state: ok=%v state=%+v err=%v", cached, state, cachedErr)
	}
	getAfterTimeout, _ := backend.calls()
	if getAfterTimeout != 1 {
		t.Fatalf("range failure cache persistence calls=%d, want 1", getAfterTimeout)
	}

	written := proxy.RangeCompatState{
		Incompatible:        true,
		ConsecutiveFailures: 5,
		LastReason:          "range_unsupported",
		LastCheckedAt:       time.Now(),
	}
	if err := store.Upsert("slow.example::/movie.mkv", written); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	getBefore, upserts := backend.calls()
	after, ok, err := store.Get("slow.example::/movie.mkv")
	if err != nil || !ok || !after.Incompatible || after.ConsecutiveFailures != 5 {
		t.Fatalf("write-through range state: ok=%v state=%+v err=%v", ok, after, err)
	}
	getAfter, upsertsAfter := backend.calls()
	if getAfter != getBefore || upserts != 1 || upsertsAfter != upserts {
		t.Fatalf("read after range write hit persistence: get=%d->%d upsert=%d->%d", getBefore, getAfter, upserts, upsertsAfter)
	}
}

func TestMySQLRangeCompatStoreCacheIsBounded(t *testing.T) {
	backend := &fakeMySQLRangeCompatPersistence{
		getFn: func(_ context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
			return rangeCompatRecord(providerHost, storageKey), true, nil
		},
	}
	store := newMySQLRangeCompatStore(backend)
	store.maxEntries = 2
	for _, key := range []string{"one.example::/one", "two.example::/two", "three.example::/three"} {
		if _, ok, err := store.Get(key); err != nil || !ok {
			t.Fatalf("Get(%q): ok=%v err=%v", key, ok, err)
		}
	}
	store.mu.RLock()
	entries := len(store.cache)
	store.mu.RUnlock()
	if entries != 2 {
		t.Fatalf("bounded range cache entries=%d, want 2", entries)
	}
}

func TestMySQLRangeCompatStoreLoadCannotOverwriteConcurrentUpsert(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := &fakeMySQLRangeCompatPersistence{
		getFn: func(_ context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
			close(entered)
			<-release
			return rangeCompatRecord(providerHost, storageKey), true, nil
		},
	}
	store := newMySQLRangeCompatStore(backend)
	type loadResult struct {
		state proxy.RangeCompatState
		ok    bool
		err   error
	}
	loaded := make(chan loadResult, 1)
	go func() {
		state, ok, err := store.Get("race.example::/movie.mkv")
		loaded <- loadResult{state: state, ok: ok, err: err}
	}()
	<-entered

	written := proxy.RangeCompatState{
		Incompatible:         false,
		ConsecutiveSuccesses: 9,
		LastCheckedAt:        time.Now(),
	}
	if err := store.Upsert("race.example::/movie.mkv", written); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	close(release)
	result := <-loaded
	if result.err != nil || !result.ok || result.state.Incompatible || result.state.ConsecutiveSuccesses != 9 {
		t.Fatalf("in-flight load returned stale DB state: %+v", result)
	}
	after, ok, err := store.Get("race.example::/movie.mkv")
	if err != nil || !ok || after.Incompatible || after.ConsecutiveSuccesses != 9 {
		t.Fatalf("in-flight load overwrote Upsert: ok=%v state=%+v err=%v", ok, after, err)
	}
}

func TestMySQLRangeCompatStoreRetriesDirtyWriteAfterPersistenceError(t *testing.T) {
	persistErr := errors.New("temporary persistence failure")
	attempts := 0
	backend := &fakeMySQLRangeCompatPersistence{
		upsertFn: func(context.Context, mysqlstore.RangeCompatRecord) error {
			attempts++
			if attempts == 1 {
				return persistErr
			}
			return nil
		},
	}
	store := newMySQLRangeCompatStore(backend)
	state := proxy.RangeCompatState{
		Incompatible:        true,
		ConsecutiveFailures: 5,
		LastReason:          "range_unsupported",
		LastCheckedAt:       time.Now(),
	}
	key := "dirty.example::/movie.mkv"
	if err := store.Upsert(key, state); !errors.Is(err, persistErr) {
		t.Fatalf("first Upsert error=%v, want %v", err, persistErr)
	}
	if cached, ok, err := store.Get(key); err != nil || !ok || cached.ConsecutiveFailures != 5 {
		t.Fatalf("failed write was not retained for read-through: ok=%v state=%+v err=%v", ok, cached, err)
	}
	if err := store.Upsert(key, state); err != nil {
		t.Fatalf("retry Upsert: %v", err)
	}
	if err := store.Upsert(key, state); err != nil {
		t.Fatalf("persisted duplicate Upsert: %v", err)
	}
	_, upserts := backend.calls()
	if upserts != 2 {
		t.Fatalf("range persistence attempts=%d, want 2", upserts)
	}
}

func TestMySQLRangeCompatStoreGenerationSurvivesWriteCacheEviction(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	backend := &fakeMySQLRangeCompatPersistence{
		getFn: func(_ context.Context, providerHost, storageKey string) (*mysqlstore.RangeCompatRecord, bool, error) {
			if providerHost == "race-evict.example" {
				close(entered)
				<-release
				return rangeCompatRecord(providerHost, storageKey), true, nil
			}
			return rangeCompatRecord(providerHost, storageKey), true, nil
		},
	}
	store := newMySQLRangeCompatStore(backend)
	store.maxEntries = 1
	type result struct {
		state proxy.RangeCompatState
		ok    bool
		err   error
	}
	loaded := make(chan result, 1)
	go func() {
		state, ok, err := store.Get("race-evict.example::/movie.mkv")
		loaded <- result{state: state, ok: ok, err: err}
	}()
	<-entered

	written := proxy.RangeCompatState{
		Incompatible:         false,
		ConsecutiveSuccesses: 10,
		LastCheckedAt:        time.Now(),
	}
	if err := store.Upsert("race-evict.example::/movie.mkv", written); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, ok, err := store.Get("evictor.example::/other.mkv"); err != nil || !ok {
		t.Fatalf("load evictor range state: ok=%v err=%v", ok, err)
	}
	close(release)

	resultAfterEviction := <-loaded
	if resultAfterEviction.err != nil || resultAfterEviction.ok {
		t.Fatalf("stale range load escaped after write cache eviction: %+v", resultAfterEviction)
	}
	store.mu.RLock()
	_, staleCached := store.cache["race-evict.example::/movie.mkv"]
	store.mu.RUnlock()
	if staleCached {
		t.Fatal("stale range load repopulated the evicted write")
	}
}
