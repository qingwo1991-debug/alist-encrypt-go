package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/httputil"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// This is a distinct authenticated-record budget, never the legacy output cache.
// Owned resident, reserved, and evicted-but-pinned plaintext together stay <=64MiB.
// The existing 256MiB admission separately covers sequential ciphertext buffers.
var rootV3RecordCache = encryption.NewV3AuthenticatedRecordCache(64<<20, 30*time.Second)

type v3AuthorizationKey struct{}
type v3Authorization struct{ authorization, cookie string }

// WithV3CacheAuthorization is called only AFTER route access checks. Empty
// credentials explicitly mean verified anonymous, not an absent scope. Provider
// request headers remain independently bound to this originating credential.
func WithV3CacheAuthorization(ctx context.Context, authorization, cookie string) context.Context {
	return context.WithValue(ctx, v3AuthorizationKey{}, v3Authorization{authorization, cookie})
}

type v3CachePlanKey struct{}
type v3CachePlan struct {
	key                   encryption.V3RecordCacheKey
	leases                []*encryption.V3RecordLease
	readers               []io.Reader
	start, tailStart, end int64
}

func (p *v3CachePlan) release() {
	for _, l := range p.leases {
		l.Release()
	}
	p.leases = nil
}
func v3Plan(req *http.Request) *v3CachePlan {
	p, _ := req.Context().Value(v3CachePlanKey{}).(*v3CachePlan)
	return p
}

func v3CacheIdentity(req *http.Request, target string, passwd *config.PasswdInfo, meta encryption.ContentMeta, object string) (encryption.V3RecordCacheKey, bool) {
	var zero encryption.V3RecordCacheKey
	if req == nil || passwd == nil || !passwd.Enable || !meta.IsV3() {
		return zero, false
	}
	auth, verified := req.Context().Value(v3AuthorizationKey{}).(v3Authorization)
	if !verified {
		return zero, false
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return zero, false
	}
	// Canonical Header.Write sorts names. Bind ALL provider headers, not merely
	// Authorization: providers can use cookies, UA, Referer or custom credentials.
	headers := req.Header.Clone()
	headers.Del("Range")
	headers.Del("Accept-Encoding")
	var b strings.Builder
	_ = headers.Write(&b)
	scope := fmt.Sprintf("%d:%s%d:%s%s", len(auth.authorization), auth.authorization, len(auth.cookie), auth.cookie, b.String())
	digest := sha256.Sum256([]byte(scope))
	if object == "" {
		object = target
	}
	key, err := encryption.NewV3RecordCacheKey(encryption.V3RecordIdentity{
		Provider: u.Scheme + "://" + u.Host, Object: object, URL: target, Scope: "verified:" + hex.EncodeToString(digest[:]), Password: passwd.Password,
		Version: int64(meta.Version), HeaderSize: meta.HeaderLen, PlainSize: meta.PlainSize, CipherSize: meta.CiphertextSize, ChunkSize: int64(meta.ChunkSize), KDFIterations: meta.KDFIterations, Nonce: meta.NonceField,
	})
	return key, err == nil
}

// prepareV3Cache pins only a bounded contiguous prefix. Its original interval is
// never changed: only the upstream Range begins at the first missing record.
func prepareV3Cache(req *http.Request, target string, passwd *config.PasswdInfo, meta encryption.ContentMeta, rangeHeader, object string, strategy StreamStrategy) (*http.Request, string, *v3CachePlan) {
	if req.Method != http.MethodGet || rangeHeader == "" || !meta.IsV3() {
		return req, rangeHeader, nil
	}
	key, ok := v3CacheIdentity(req, target, passwd, meta, object)
	if !ok {
		return req, rangeHeader, nil
	}
	parsed, err := httputil.ParseRange(rangeHeader, meta.PlainSize)
	if err != nil || parsed == nil || len(parsed.Ranges) != 1 {
		return req, rangeHeader, nil
	}
	r := parsed.Ranges[0]
	p := &v3CachePlan{key: key, start: r.Start, tailStart: r.Start, end: r.End}
	chunk := int64(meta.ChunkSize)
	pinned := int64(0)
	for p.tailStart <= p.end {
		idx := p.tailStart / chunk
		l, hit := rootV3RecordCache.Get(key, uint64(idx))
		if !hit {
			break
		}
		if pinned+chunk > 16<<20 {
			l.Release()
			break
		}
		pinned += chunk
		offset := p.tailStart % chunk
		length := l.Len() - offset
		if length > p.end-p.tailStart+1 {
			length = p.end - p.tailStart + 1
		}
		if length <= 0 {
			l.Release()
			break
		}
		p.leases = append(p.leases, l)
		p.readers = append(p.readers, io.NewSectionReader(l, offset, length))
		p.tailStart += length
	}
	// Prefix optimization requires an exact Range transport. Full/Chunked retain
	// their original skip-budget semantics; only a complete hit bypasses transport.
	if p.tailStart <= p.end && strategy != StreamStrategyRange {
		p.release()
		p.tailStart = p.start
		p.readers = nil
	}
	req = req.WithContext(context.WithValue(req.Context(), v3CachePlanKey{}, p))
	return req, fmt.Sprintf("bytes=%d-%d", p.tailStart, p.end), p
}

type v3CacheContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r v3CacheContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func serveV3Cache(w http.ResponseWriter, req *http.Request, p *v3CachePlan, size int64) *StreamOutcome {
	if err := req.Context().Err(); err != nil {
		return &StreamOutcome{Err: err, FailureReason: "client_disconnect", NoLearning: true}
	}
	for _, name := range []string{"Content-Encoding", "Transfer-Encoding", "ETag", "Content-Type", "Last-Modified"} {
		w.Header().Del(name)
	}
	r := httputil.Range{Start: p.start, End: p.end}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", r.ContentRangeHeader(size))
	w.Header().Set("Content-Length", strconv.FormatInt(r.ContentLength(), 10))
	w.WriteHeader(http.StatusPartialContent)
	n, err := io.Copy(w, v3CacheContextReader{req.Context(), io.MultiReader(p.readers...)})
	out := &StreamOutcome{BytesWritten: n, ExpectedBytes: r.ContentLength(), ResponseStarted: true, StatusCode: http.StatusPartialContent, Err: err}
	if err != nil {
		out.FailureReason = "cache_write_error"
		out.NoLearning = true
	}
	return out
}

// A single upstream body supplies every miss. If cache hits skip records, the
// next miss discards exactly those encrypted records to restore body alignment.
func sequentialV3Loader(body io.Reader, first, chunk int64) encryption.V3RawRecordLoader {
	next := uint64(first)
	var raw []byte // one reusable admitted ciphertext buffer, never cached
	return func(ctx context.Context, index uint64) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if index < next {
			return nil, fmt.Errorf("v3: backward record transport")
		}
		if err := discardBytes(body, int64(index-next)*(chunk+16)); err != nil {
			return nil, err
		}
		if raw == nil {
			raw = make([]byte, chunk+16)
		}
		if _, err := io.ReadFull(body, raw); err != nil {
			return nil, err
		}
		next = index + 1
		return raw, nil
	}
}
