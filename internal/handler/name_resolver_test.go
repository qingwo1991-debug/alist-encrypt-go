package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

func newResolverTestDAO(t *testing.T) *dao.FileDAO {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return dao.NewFileDAO(store)
}

func TestNameResolverUpstreamBasename(t *testing.T) {
	passwd := testEncPasswd()
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)

	t.Run("cached mapping wins", func(t *testing.T) {
		d := newResolverTestDAO(t)
		d.SetEncPathMapping("/encrypt/movie.mp4", "/encrypt/"+converter.ToRealName("movie.mp4"))
		nr := newNameResolver(d, passwd)
		if got := nr.upstreamBasename("/encrypt", "movie.mp4", func() bool { t.Fatal("probe must not run"); return false }); got != converter.ToRealName("movie.mp4") {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("plaintext object keeps spelling when probe hits", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		if got := nr.upstreamBasename("/encrypt", "readme.txt", func() bool { return true }); got != "readme.txt" {
			t.Fatalf("got %q, want readme.txt", got)
		}
	})

	t.Run("absent name is encrypted", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		want := converter.ToRealName("movie.mp4")
		if got := nr.upstreamBasename("/encrypt", "movie.mp4", func() bool { return false }); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("orig_ prefix strips to literal", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		if got := nr.upstreamBasename("/encrypt", "orig_plain.txt", func() bool { return false }); got != "plain.txt" {
			t.Fatalf("got %q, want plain.txt", got)
		}
	})

	t.Run("already encrypted name passes through", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		enc := converter.ToRealName("movie.mp4")
		if got := nr.upstreamBasename("/encrypt", enc, func() bool { return false }); got != enc {
			t.Fatalf("got %q, want %q", got, enc)
		}
	})

	t.Run("cached directory keeps spelling", func(t *testing.T) {
		d := newResolverTestDAO(t)
		d.Set(&dao.FileInfo{Path: "/encrypt/season1", Name: "season1", IsDir: true})
		nr := newNameResolver(d, passwd)
		if got := nr.upstreamBasename("/encrypt", "season1", func() bool { t.Fatal("probe must not run"); return false }); got != "season1" {
			t.Fatalf("got %q, want season1", got)
		}
	})
}

func TestNameResolverSourcePath(t *testing.T) {
	passwd := testEncPasswd()
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)

	t.Run("plaintext directory probe hit keeps spelling and isDir", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		got, isDir := nr.sourcePath("/encrypt/season1", func() (bool, bool) { return true, true })
		if got != "/encrypt/season1" || !isDir {
			t.Fatalf("got %q isDir=%v", got, isDir)
		}
	})

	t.Run("plaintext file probe hit keeps spelling", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		got, isDir := nr.sourcePath("/encrypt/readme.txt", func() (bool, bool) { return true, false })
		if got != "/encrypt/readme.txt" || isDir {
			t.Fatalf("got %q isDir=%v", got, isDir)
		}
	})

	t.Run("absent name derives encrypted path", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		want := "/encrypt/" + converter.ToRealName("movie.mp4")
		got, isDir := nr.sourcePath("/encrypt/movie.mp4", func() (bool, bool) { return false, false })
		if got != want || isDir {
			t.Fatalf("got %q isDir=%v, want %q", got, isDir, want)
		}
	})

	t.Run("orig_ strips literally without path.Join cleanup", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		got, _ := nr.sourcePath("/encrypt/orig_..", func() (bool, bool) { return false, false })
		if got != "/encrypt/.." {
			t.Fatalf("got %q, want /encrypt/..", got)
		}
	})
}

func TestNameResolverDestinationPath(t *testing.T) {
	passwd := testEncPasswd()
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)

	t.Run("directory source keeps literal destination", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		if got := nr.destinationPath("/encrypt/newdir", true); got != "/encrypt/newdir" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("file destination is encrypted", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		want := "/encrypt/" + converter.ToRealName("renamed.mp4")
		if got := nr.destinationPath("/encrypt/renamed.mp4", false); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("orig_ destination strips to plaintext", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		if got := nr.destinationPath("/encrypt/orig_keep.txt", false); got != "/encrypt/keep.txt" {
			t.Fatalf("got %q, want /encrypt/keep.txt", got)
		}
	})

	t.Run("already encrypted destination passes through", func(t *testing.T) {
		d := newResolverTestDAO(t)
		nr := newNameResolver(d, passwd)
		enc := converter.ToRealName("movie.mp4")
		if got := nr.destinationPath("/encrypt/"+enc, false); got != "/encrypt/"+enc {
			t.Fatalf("got %q, want passthrough %q", got, enc)
		}
	})

	t.Run("cached mapping wins", func(t *testing.T) {
		d := newResolverTestDAO(t)
		enc := converter.ToRealName("movie.mp4")
		d.SetEncPathMapping("/encrypt/movie.mp4", "/encrypt/"+enc)
		nr := newNameResolver(d, passwd)
		if got := nr.destinationPath("/encrypt/movie.mp4", false); got != "/encrypt/"+enc {
			t.Fatalf("got %q, want %q", got, "/encrypt/"+enc)
		}
	})
}

// WebDAV DELETE must resolve plaintext upstream objects by their real
// spelling; the old convertToRealPath blindly encrypted the display name and
// deleted a nonexistent target while reporting success.
func TestWebDAVDeleteKeepsPlaintextUpstreamName(t *testing.T) {
	var capturedPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{"is_dir": false},
		})
	})
	mux.HandleFunc("/dav/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	h, _ := newWebDAVMoveTestHandler(t, srv.URL)
	req := httptest.NewRequest(http.MethodDelete, "/dav/encrypt/readme.txt", nil)
	rec := httptest.NewRecorder()
	h.Handle(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if capturedPath != "/dav/encrypt/readme.txt" {
		t.Fatalf("upstream path = %q, want /dav/encrypt/readme.txt (plaintext object must not be encrypted)", capturedPath)
	}
}

// An absent display spelling still resolves to the encrypted upstream name.
func TestWebDAVDeleteEncryptsAbsentDisplayName(t *testing.T) {
	converter := encryption.NewFileNameConverter("testpass", "aesctr", ".bin")
	wantSuffix := "/dav/encrypt/" + converter.ToRealName("movie.mp4")

	var capturedPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fs/get", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, map[string]interface{}{
			"code":    500,
			"message": "object not found",
			"data":    nil,
		})
	})
	mux.HandleFunc("/dav/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	srv := newSocketTestServer(t, mux)
	defer srv.Close()

	h, _ := newWebDAVMoveTestHandler(t, srv.URL)
	req := httptest.NewRequest(http.MethodDelete, "/dav/encrypt/movie.mp4", nil)
	rec := httptest.NewRecorder()
	h.Handle(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if !strings.HasSuffix(capturedPath, wantSuffix) {
		t.Fatalf("upstream path = %q, want suffix %q", capturedPath, wantSuffix)
	}
}
