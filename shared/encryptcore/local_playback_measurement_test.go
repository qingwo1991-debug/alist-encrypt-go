package encryption

import (
 "bytes"
 "context"
 "fmt"
 "testing"
 "time"
)

// Cold uses the production PBKDF2, not a reduced iteration substitute. Keep this
// opt-in on a cached CI runner (-run '^$' -bench ...); do not run the full suite
// just to collect a playback sample. Derived keys never leave process memory.
func BenchmarkLocalPlaybackV2KDFCounts(b *testing.B) {
 for _, warm := range []bool{false, true} {
  b.Run(fmt.Sprintf("warm=%t", warm), func(b *testing.B) {
   password := "local-playback-counted-key"
   calls := 0
   derive := func(p, typ string, n int) []byte { calls++; return deriveV2KeyPBKDF2(p, typ, n) }
   if warm { cachedV2KeyWithDeriver(password, "aesctr", 32, derive) }
   calls = 0
   b.ReportAllocs()
   b.ResetTimer()
   for i := 0; i < b.N; i++ {
    p := password
    if !warm {
     // Explicit eviction keeps every measured iteration genuinely cold without
     // increasing retained cache entries or weakening the production KDF.
     v2KeyCacheMu.Lock(); delete(v2KeyCache, v2KeyCacheKey(p, "aesctr", 32)); v2KeyCacheMu.Unlock()
    }
    if len(cachedV2KeyWithDeriver(p, "aesctr", 32, derive)) != 32 { b.Fatal("invalid key") }
   }
   b.StopTimer()
   b.ReportMetric(float64(calls)/float64(b.N), "derivations/op")
   want := 0; if !warm { want = b.N }
   if calls != want { b.Fatalf("derivations=%d want=%d", calls, want) }
  })
 }
}

// Each size is a synthetic container geometry, not a runtime V3 chunk override.
// Cold measures full-record transport copy + authenticated Open; warm supplies a
// nil cipher and loader, proving neither transport nor authentication reruns.
func BenchmarkLocalPlaybackV3Record(b *testing.B) {
 for _, size := range []int64{64 << 10, 256 << 10, 1024 << 10} {
  for _, warm := range []bool{false, true} {
   b.Run(fmt.Sprintf("%dKiB/warm=%t", size>>10, warm), func(b *testing.B) {
    id := recordTestIdentity(); id.PlainSize = size; id.ChunkSize = size; id.CipherSize = V3HeaderSize + size + 16
    key, err := NewV3RecordCacheKey(id); if err != nil { b.Fatal(err) }
    cipher, err := NewV3ChunkCipher(bytes.Repeat([]byte{7}, 32), id.Nonce); if err != nil { b.Fatal(err) }
    plain := bytes.Repeat([]byte{0x2a}, int(size))
    raw, err := cipher.Seal(0, plain); if err != nil { b.Fatal(err) }
    cache := NewV3AuthenticatedRecordCache(64<<20, 30*time.Second)
    loads := 0
    loader := func(context.Context, uint64) ([]byte, error) { loads++; return append([]byte(nil), raw...), nil }
    if warm { l, err := cache.Load(context.Background(), key, 0, cipher, size, size, loader); if err != nil { b.Fatal(err) }; l.Release() }
    loads = 0
    out := make([]byte, size)
    b.ReportAllocs(); b.SetBytes(size); b.ResetTimer()
    for i := 0; i < b.N; i++ {
     if !warm { cache = NewV3AuthenticatedRecordCache(64<<20, 30*time.Second) }
     var l *V3RecordLease
     var err error
     if warm { l, err = cache.Load(context.Background(), key, 0, nil, size, size, nil) } else { l, err = cache.Load(context.Background(), key, 0, cipher, size, size, loader) }
     if err != nil { b.Fatal(err) }
     n, err := l.ReadAt(out, 0); l.Release()
     if err != nil || int64(n) != size || out[0] != 0x2a { b.Fatalf("read=%d err=%v", n, err) }
    }
    b.StopTimer()
    b.ReportMetric(float64(loads)/float64(b.N), "record_loads/op")
    b.ReportMetric(float64(loads)/float64(b.N), "authenticated_opens/op")
    b.ReportMetric(0, "identity_hashes/op") // key built once outside timed data path
    want := 0; if !warm { want = b.N }; if loads != want { b.Fatalf("loads=%d want=%d", loads, want) }
   })
  }
 }
}

func BenchmarkLocalPlaybackV3IdentityHash(b *testing.B) {
 id := recordTestIdentity()
 b.ReportAllocs()
 for i := 0; i < b.N; i++ { if _, err := NewV3RecordCacheKey(id); err != nil { b.Fatal(err) } }
 b.ReportMetric(1, "identity_hashes/op") // includes password SHA256 and domain-separated identity SHA256
}
