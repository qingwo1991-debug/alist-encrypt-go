package handler

import (
	"net/http/httptest"
	"testing"
)

func TestProtectedMutationDAVResolvedOriginalPrefix(t *testing.T) {
	for _, method := range []string{"MOVE", "COPY"} {
		h, _, _ := newWebDAVSnapshotTestHandler(t)
		defer h.Stop()
		h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/156联通云盘/encrypt/protected": 100}
		for _, tc := range []struct{ source, destination string }{
			{"/156联通云盘/encrypt/orig_protected", "/dav/outside/new"},
			{"/156联通云盘/encrypt/orig_safe", "/dav/156联通云盘/encrypt/orig_protected"},
		} {
			req := httptest.NewRequest(method, "http://example.com/dav"+tc.source, nil)
			req.Header.Set("Destination", tc.destination)
			rec := httptest.NewRecorder()
			h.handleMoveOrCopy(rec, req, tc.source, method)
			if rec.Code != 501 {
				t.Fatalf("%s resolved path bypass: %d %s", method, rec.Code, rec.Body.String())
			}
		}
	}
}
