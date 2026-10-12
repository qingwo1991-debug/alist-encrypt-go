package encryption

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func recordTestIdentity() V3RecordIdentity {
	return V3RecordIdentity{Provider: "server/provider", Object: "encrypted/object", URL: "https://example/object?token=one", Scope: "authorized:scope", Password: "secret", Version: 3, HeaderSize: 48, PlainSize: 130, CipherSize: 48 + 3*(64+16) + 16, ChunkSize: 64, Nonce: bytes.Repeat([]byte{9}, 16)}
}
func recordTestKey(t testing.TB) V3RecordCacheKey {
	t.Helper()
	key, err := NewV3RecordCacheKey(recordTestIdentity())
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func recordLoader(t testing.TB, c *V3ChunkCipher, plain []byte, cs int64, calls *int) V3RawRecordLoader {
	t.Helper()
	return func(ctx context.Context, index uint64) ([]byte, error) {
		*calls++
		p := make([]byte, cs)
		off := int64(index) * cs
		copy(p, plain[off:])
		return c.Seal(index, p)
	}
}
func leaseBytes(t testing.TB, l *V3RecordLease) []byte {
	t.Helper()
	p := make([]byte, l.Len())
	if _, err := l.ReadAt(p, 0); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestV3AuthenticatedRecordIdentityIsolation(t *testing.T) {
	id := recordTestIdentity()
	base, err := NewV3RecordCacheKey(id)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*V3RecordIdentity){
		"provider": func(i *V3RecordIdentity) { i.Provider += "2" }, "object": func(i *V3RecordIdentity) { i.Object += "2" }, "password": func(i *V3RecordIdentity) { i.Password += "2" }, "scope": func(i *V3RecordIdentity) { i.Scope += "2" }, "url": func(i *V3RecordIdentity) { i.URL += "2" }, "revision": func(i *V3RecordIdentity) { i.Revision = "etag-2" }, "nonce": func(i *V3RecordIdentity) { i.Nonce[0]++ }, "kdf": func(i *V3RecordIdentity) { i.KDFIterations = 600001 }, "plain-size": func(i *V3RecordIdentity) { i.PlainSize++ }, "chunk": func(i *V3RecordIdentity) { i.ChunkSize = 65; i.CipherSize = 48 + 2*81 + 16 }, "cipher-size": func(i *V3RecordIdentity) { i.CipherSize -= 16 },
	} {
		t.Run(name, func(t *testing.T) {
			next := id
			next.Nonce = append([]byte(nil), id.Nonce...)
			mutate(&next)
			key, err := NewV3RecordCacheKey(next)
			if err != nil || key == base {
				t.Fatalf("not isolated: %v", err)
			}
		})
	}
	normalized := id
	normalized.KDFIterations = 600000
	same, _ := NewV3RecordCacheKey(normalized)
	if same != base {
		t.Fatal("KDF normalization differs")
	}
	id.Revision = "trusted-etag"
	stable, _ := NewV3RecordCacheKey(id)
	id.URL += "&rotation=2"
	rotated, _ := NewV3RecordCacheKey(id)
	if stable != rotated {
		t.Fatal("trusted revision URL rotation missed")
	}
	for _, mutate := range []func(*V3RecordIdentity){func(i *V3RecordIdentity) { i.Scope = "" }, func(i *V3RecordIdentity) { i.Provider = "" }, func(i *V3RecordIdentity) { i.Object = "" }, func(i *V3RecordIdentity) { i.HeaderSize++ }, func(i *V3RecordIdentity) { i.Version = 2 }, func(i *V3RecordIdentity) { i.CipherSize++ }, func(i *V3RecordIdentity) { i.Nonce = nil }, func(i *V3RecordIdentity) { i.ChunkSize = 0 }, func(i *V3RecordIdentity) { i.PlainSize = -1 }, func(i *V3RecordIdentity) { i.PlainSize = 1 << 62 }, func(i *V3RecordIdentity) { i.Revision = ""; i.URL = "" }} {
		invalid := id
		mutate(&invalid)
		if _, err := NewV3RecordCacheKey(invalid); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
func TestV3AuthenticatedRecordTinyRangesAvoidTransportAndTrim(t *testing.T) {
	c, want, _ := v3MemoryFixture(t, 64, 130)
	cache := NewV3AuthenticatedRecordCache(192, time.Minute)
	key := recordTestKey(t)
	calls := 0
	loader := recordLoader(t, c.Cipher, want, 64, &calls)
	for _, r := range [][2]int64{{0, 2}, {62, 2}, {63, 4}, {128, 2}} {
		reader, err := NewV3RecordReader(context.Background(), c.Cipher, 64, r[0]/64, r[0]%64, r[1], 130, cache, key, loader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(got, want[r[0]:r[0]+r[1]]) {
			t.Fatalf("range %v: %x %v", r, got, err)
		}
	}
	if calls != 3 {
		t.Fatalf("transport/auth misses %d, want 3", calls)
	}
	tail, ok := cache.Get(key, 2)
	if !ok || tail.Len() != 2 {
		t.Fatal("cached padding exposed")
	}
	tail.Release()
	// Cache hit can be consumed before deriving any cipher or constructing loader.
	reader, err := NewV3RecordReader(context.Background(), nil, 64, 0, 7, 2, 130, cache, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(got, want[7:9]) {
		t.Fatalf("key-free hit %x %v", got, err)
	}
}
func TestV3AuthenticatedRecordTamperNeverPublishes(t *testing.T) {
	cipher := v3MemoryCipher(t)
	cache := NewV3AuthenticatedRecordCache(128, time.Minute)
	key := recordTestKey(t)
	raw, _ := cipher.Seal(0, bytes.Repeat([]byte{42}, 64))
	raw[4] ^= 1
	loader := func(context.Context, uint64) ([]byte, error) { return raw, nil }
	for i := 0; i < 2; i++ {
		l, err := cache.Load(context.Background(), key, 0, cipher, 64, 130, loader)
		if l != nil || !errors.Is(err, errV3TagMismatch) {
			t.Fatalf("tamper %v %v", l, err)
		}
		if _, hit := cache.Get(key, 0); hit || cache.Stats().OwnedBytes != 0 {
			t.Fatal("failed authentication cached/leaked")
		}
	}
	good, _ := cipher.Seal(0, bytes.Repeat([]byte{42}, 64))
	loader = func(context.Context, uint64) ([]byte, error) { return good, nil }
	bad, _ := NewV3ChunkCipher(bytes.Repeat([]byte{8}, 32), cipher.nonce)
	if l, err := cache.Load(context.Background(), key, 0, bad, 64, 130, loader); l != nil || !errors.Is(err, errV3TagMismatch) {
		t.Fatal("wrong password accepted")
	}
	if l, err := cache.Load(context.Background(), key, 0, nil, 64, 130, loader); l != nil || err == nil {
		t.Fatal("nil cipher accepted")
	}
	if l, err := cache.Load(context.Background(), V3RecordCacheKey{}, 0, cipher, 64, 130, loader); l != nil || err == nil {
		t.Fatal("zero identity accepted")
	}
	if l, err := cache.Load(context.Background(), key, 0, cipher, 64, 130, func(context.Context, uint64) ([]byte, error) { return good[:10], nil }); l != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("truncated record accepted")
	}
	l, err := cache.Load(context.Background(), key, 0, cipher, 64, 130, loader)
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
}
func TestV3AuthenticatedRecordBudgetEvictionTTLAndLease(t *testing.T) {
	cipher := v3MemoryCipher(t)
	cache := NewV3AuthenticatedRecordCache(64, time.Minute)
	key := recordTestKey(t)
	calls := 0
	plain := bytes.Repeat([]byte{1}, 130)
	loader := recordLoader(t, cipher, plain, 64, &calls)
	now := time.Now()
	cache.now = func() time.Time { return now }
	first, err := cache.Load(context.Background(), key, 0, cipher, 64, 130, loader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(context.Background(), key, 1, cipher, 64, 130, loader); !errors.Is(err, ErrV3RecordCacheFull) || calls != 1 {
		t.Fatalf("pinned budget bypass %v calls %d", err, calls)
	}
	s := cache.Stats()
	if s.OwnedBytes != 64 || s.PinnedEvictedBytes != 64 || s.Entries != 0 {
		t.Fatalf("ownership %+v", s)
	}
	p := leaseBytes(t, first)
	p[0] = 9
	if leaseBytes(t, first)[0] != 1 {
		t.Fatal("mutable returned ownership")
	}
	first.Release()
	first.Release()
	if cache.Stats().OwnedBytes != 0 {
		t.Fatal("lease leak")
	}
	if _, err := first.ReadAt(p, 0); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("released readable")
	}
	second, err := cache.Load(context.Background(), key, 1, cipher, 64, 130, loader)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, ok := cache.Get(key, 1); ok {
		t.Fatal("expired hit")
	}
	if cache.Stats().PinnedEvictedBytes != 64 {
		t.Fatal("TTL lost pinned accounting")
	}
	second.Release()
	if cache.Stats().OwnedBytes != 0 {
		t.Fatal("TTL release leak")
	}
	if _, err := cache.Load(context.Background(), key, 0, cipher, 65, 130, loader); !errors.Is(err, ErrV3RecordCacheFull) {
		t.Fatalf("oversize accepted: %v", err)
	}
}
func TestV3AuthenticatedRecordCancellationAndReservation(t *testing.T) {
	cipher := v3MemoryCipher(t)
	cache := NewV3AuthenticatedRecordCache(64, time.Minute)
	key := recordTestKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	loader := recordLoader(t, cipher, bytes.Repeat([]byte{2}, 130), 64, &calls)
	if _, err := cache.Load(ctx, key, 0, cipher, 64, 130, loader); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("canceled loader ran")
	}
	ctx, cancel = context.WithCancel(context.Background())
	if _, err := cache.Load(ctx, key, 0, cipher, 64, 130, func(ctx context.Context, i uint64) ([]byte, error) { cancel(); return loader(ctx, i) }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if cache.Stats().OwnedBytes != 0 {
		t.Fatal("cancel reservation leaked")
	}
	entered := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		l, err := cache.Load(context.Background(), key, 0, cipher, 64, 130, func(ctx context.Context, i uint64) ([]byte, error) { close(entered); <-finish; return loader(ctx, i) })
		if l != nil {
			l.Release()
		}
		done <- err
	}()
	<-entered
	if s := cache.Stats(); s.ReservedBytes != 64 || s.OwnedBytes > 64 {
		t.Fatalf("reservation %+v", s)
	}
	if _, err := cache.Load(context.Background(), key, 1, cipher, 64, 130, loader); !errors.Is(err, ErrV3RecordCacheFull) {
		t.Fatal("parallel reservation bypass")
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestV3AuthenticatedRecordStreamPublishesImmutableWholeChunks(t *testing.T) {
	c, want, data := v3MemoryFixture(t, 64, 130)
	cache := NewV3AuthenticatedRecordCache(192, time.Minute)
	key := recordTestKey(t)
	r, err := NewV3StreamReaderWithCache(bytes.NewReader(data[V3HeaderSize:]), c.Cipher, 64, 0, 7, 123, cache, key, 130)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(got, want[7:]) {
		t.Fatalf("stream %v", err)
	}
	for i := uint64(0); i < 3; i++ {
		l, ok := cache.Get(key, i)
		if !ok {
			t.Fatal("whole chunk missing")
		}
		end := int(i+1) * 64
		if end > len(want) {
			end = len(want)
		}
		if !bytes.Equal(leaseBytes(t, l), want[int(i)*64:end]) {
			t.Fatal("record reuse corrupted immutable copy")
		}
		l.Release()
	}
}
func TestV3AuthenticatedRecordConcurrentLeases(t *testing.T) {
	c, want, _ := v3MemoryFixture(t, 64, 130)
	cache := NewV3AuthenticatedRecordCache(192, time.Minute)
	key := recordTestKey(t)
	calls := 0
	l, err := cache.Load(context.Background(), key, 0, c.Cipher, 64, 130, recordLoader(t, c.Cipher, want, 64, &calls))
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, ok := cache.Get(key, 0)
			if !ok {
				t.Error("hit missing")
				return
			}
			p := make([]byte, 4)
			if _, err := l.ReadAt(p, 4); err != nil || !bytes.Equal(p, want[4:8]) {
				t.Error("wrong lease bytes")
			}
			l.Release()
		}()
	}
	wg.Wait()
	if cache.Stats().OwnedBytes > cache.Stats().MaxBytes {
		t.Fatal("over budget")
	}
}
