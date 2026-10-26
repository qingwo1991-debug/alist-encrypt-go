package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// OpenList creates the entry script from a preload descriptor at runtime;
// browser-detection modules are already present in the original document.
const previewShellDocumentFixture = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<script>window.OPENLIST_CONFIG = {cdn:'',base_path:'/',api:undefined}; window.__dynamic_base__ = window.OPENLIST_CONFIG.cdn || "";</script>
<script type="module">import.meta.url; import('_').catch(()=>1);</script>
</head><body><div id="root"></div><script>
var preloads = [{"parentTagName":"head","tagName":"script","attrs":{"type":"module","src":"/assets/index-example.js"}}];
</script></body></html>`

func previewShellTestResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}}}
}

func TestPreviewShellInjectDocument(t *testing.T) {
	for _, source := range []string{
		previewShellDocumentFixture,
		strings.Replace(previewShellDocumentFixture, `<div id="root">`, `<DIV class='mount' ID='root'>`, 1),
		strings.Replace(previewShellDocumentFixture, `</head>`, `</HEAD >`, 1),
	} {
		r := httptest.NewRequest(http.MethodGet, "http://example.test/folder/movie.html", nil)
		r.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		resp := previewShellTestResponse()
		resp.Header.Set("ETag", `"upstream"`)
		beforeHeaders := resp.Header.Clone()
		out, modified := injectPreviewShell(r, resp, []byte(source))
		if !modified || bytes.Count(out, []byte(previewShellPrefix+"v1.js")) != 1 || bytes.Count(out, []byte(previewShellPrefix+"v1.css")) != 1 {
			t.Fatalf("expected exactly one asset pair, modified=%v body=%s", modified, out)
		}
		if !reflect.DeepEqual(resp.Header, beforeHeaders) {
			t.Fatal("helper mutated original response headers")
		}
		// Removing the inserted tags must restore every original byte.
		tags := `<link rel="stylesheet" href="` + previewShellPrefix + `v1.css"><script defer src="` + previewShellPrefix + `v1.js"></script>`
		if string(bytes.Replace(out, []byte(tags), nil, 1)) != source {
			t.Fatal("injection changed upstream markup")
		}
		second, again := injectPreviewShell(r, resp, out)
		if again || !bytes.Equal(second, out) {
			t.Fatal("injection was not idempotent")
		}
	}
}

func TestPreviewShellRejectResponse(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request, *http.Response)
	}{
		{"head", func(r *http.Request, _ *http.Response) { r.Method = http.MethodHead }},
		{"post", func(r *http.Request, _ *http.Response) { r.Method = http.MethodPost }},
		{"error", func(_ *http.Request, s *http.Response) { s.StatusCode = 404 }},
		{"partial", func(_ *http.Request, s *http.Response) { s.StatusCode = 206 }},
		{"redirect", func(_ *http.Request, s *http.Response) { s.StatusCode = 302 }},
		{"notmodified", func(_ *http.Request, s *http.Response) { s.StatusCode = 304 }},
		{"invalidmime", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Type", "text/html-something") }},
		{"svg", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Type", "image/svg+xml") }},
		{"json", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Type", "application/json") }},
		{"charset", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Type", "text/html; charset=utf-16") }},
		{"multimime", func(_ *http.Request, s *http.Response) { s.Header.Add("Content-Type", "text/html") }},
		{"gzip", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Encoding", "gzip") }},
		{"br", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Encoding", "br") }},
		{"multiencoding", func(_ *http.Request, s *http.Response) { s.Header["Content-Encoding"] = []string{"identity", "gzip"} }},
		{"attachment", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Disposition", "attachment") }},
		{"inlinefile", func(_ *http.Request, s *http.Response) {
			s.Header.Set("Content-Disposition", "inline; filename=movie.html")
		}},
		{"range", func(r *http.Request, _ *http.Response) { r.Header.Set("Range", "bytes=0-100") }},
		{"contentrange", func(_ *http.Request, s *http.Response) { s.Header.Set("Content-Range", "bytes 0-99/100") }},
		{"cspnonce", func(_ *http.Request, s *http.Response) {
			s.Header.Set("Content-Security-Policy", "script-src 'nonce-test'; style-src 'self'")
		}},
		{"cspmultiple", func(_ *http.Request, s *http.Response) {
			s.Header["Content-Security-Policy"] = []string{"", "script-src 'none'"}
		}},
		{"cspreportonly", func(_ *http.Request, s *http.Response) {
			s.Header.Set("Content-Security-Policy-Report-Only", "default-src 'self'")
		}},
		{"notransform", func(_ *http.Request, s *http.Response) { s.Header.Add("Cache-Control", "public, No-Transform") }},
		{"requestnotransform", func(r *http.Request, _ *http.Response) { r.Header.Set("Cache-Control", "no-transform") }},
		{"subresource", func(r *http.Request, _ *http.Response) { r.Header.Set("Sec-Fetch-Dest", "script") }},
		{"iframe", func(r *http.Request, _ *http.Response) { r.Header.Set("Sec-Fetch-Dest", "iframe") }},
		{"fetch", func(r *http.Request, _ *http.Response) { r.Header.Set("Sec-Fetch-Mode", "cors") }},
		{"acceptjson", func(r *http.Request, _ *http.Response) { r.Header.Set("Accept", "application/json") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, resp := httptest.NewRequest(http.MethodGet, "http://example.test/files", nil), previewShellTestResponse()
			test.mutate(r, resp)
			headers := resp.Header.Clone()
			out, changed := injectPreviewShell(r, resp, []byte(previewShellDocumentFixture))
			if changed || string(out) != previewShellDocumentFixture || !reflect.DeepEqual(headers, resp.Header) {
				t.Fatal("rejected response was modified")
			}
		})
	}
}

func TestPreviewShellRejectPaths(t *testing.T) {
	for _, p := range []string{"/api", "/api/fs/get", "/enc-api/login", "/enc/", "/d/file.html", "/p/file.html", "/dav/file.html", "/download/file.html", "/downloads/file.html", "/@manage", "/admin/", "/assets/app.html", "/images/file.html", "/__aeg/other", "/foo/../api/fs/get", "/API/fs/get"} {
		t.Run(p, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test"+p, nil)
			if _, changed := injectPreviewShell(r, previewShellTestResponse(), []byte(previewShellDocumentFixture)); changed {
				t.Fatal("injected a non-document route")
			}
		})
	}
}

func TestPreviewShellRejectMarkup(t *testing.T) {
	tests := map[string]string{
		"genericroot":      `<!doctype html><html><head><script type="module">0</script></head><body><div id="root"></div></body></html>`,
		"commentroot":      strings.Replace(previewShellDocumentFixture, `<div id="root"></div>`, `<!-- <div id="root"></div> -->`, 1),
		"scriptroot":       strings.Replace(previewShellDocumentFixture, `<div id="root"></div>`, `<script>var root='<div id="root"></div>'</script>`, 1),
		"commentbootstrap": strings.Replace(previewShellDocumentFixture, `<script>window.OPENLIST_CONFIG`, `<!-- <script>window.OPENLIST_CONFIG`, 1),
		"configmissing":    strings.ReplaceAll(previewShellDocumentFixture, "OPENLIST_CONFIG", "OTHER_CONFIG"),
		"dynamicmissing":   strings.ReplaceAll(previewShellDocumentFixture, "__dynamic_base__", "other_base"),
		"nomodule":         strings.ReplaceAll(previewShellDocumentFixture, `type="module"`, `type="text/javascript"`),
		"duplicateattr":    strings.Replace(previewShellDocumentFixture, `<div id="root">`, `<div id="other" id="root">`, 1),
		"duplicateroot":    strings.Replace(previewShellDocumentFixture, `<div id="root"></div>`, `<div id="root"></div><div id="root"></div>`, 1),
		"base":             strings.Replace(previewShellDocumentFixture, "<head>", `<head><base href="https://evil.test/">`, 1),
		"relativebase":     strings.Replace(previewShellDocumentFixture, "<head>", `<head><base href="/">`, 1),
		"metacsp":          strings.Replace(previewShellDocumentFixture, "<head>", `<head><META HTTP-EQUIV='Content-Security-Policy' content="script-src 'none'">`, 1),
		"metareportonly":   strings.Replace(previewShellDocumentFixture, "<head>", `<head><meta http-equiv="content-security-policy-report-only" content="default-src 'self'">`, 1),
		"refresh":          strings.Replace(previewShellDocumentFixture, "<head>", `<head><meta http-equiv="refresh" content="0;url=/other">`, 1),
		"templateroot":     strings.Replace(previewShellDocumentFixture, `<div id="root"></div>`, `<template><div id="root"></div></template>`, 1),
		"svgroot":          strings.Replace(previewShellDocumentFixture, `<div id="root"></div>`, `<svg><foreignObject><div id="root"></div></foreignObject></svg>`, 1),
		"nodoctype":        strings.Replace(previewShellDocumentFixture, "<!DOCTYPE html>", "", 1),
		"truncated":        strings.Replace(previewShellDocumentFixture, "</body></html>", "", 1),
		"rootinhead":       strings.Replace(strings.Replace(previewShellDocumentFixture, `<div id="root"></div>`, "", 1), "<head>", `<head><div id="root"></div>`, 1),
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			out, changed := injectPreviewShell(httptest.NewRequest(http.MethodGet, "http://example.test/", nil), previewShellTestResponse(), []byte(source))
			if changed || string(out) != source {
				t.Fatal("injected unrecognized or unsafe markup")
			}
		})
	}
}

func TestPreviewShellAsset(t *testing.T) {
	for _, asset := range []struct {
		suffix, mime string
		body         []byte
	}{
		{"v1.js", "text/javascript; charset=utf-8", previewShellJS},
		{"v1.css", "text/css; charset=utf-8", previewShellCSS},
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(asset.suffix+method, func(t *testing.T) {
				r := httptest.NewRequest(method, "http://example.test"+previewShellPrefix+asset.suffix+"?token=not-reflected", nil)
				r.Header.Set("Authorization", "Bearer not-reflected")
				w := httptest.NewRecorder()
				if !servePreviewShellAsset(w, r) {
					t.Fatal("asset was not handled")
				}
				if method != http.MethodGet && method != http.MethodHead {
					if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || w.Body.Len() != 0 {
						t.Fatal("unsafe asset method accepted")
					}
					return
				}
				if w.Code != 200 || w.Header().Get("Content-Type") != asset.mime || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-cache" {
					t.Fatal("incorrect asset headers")
				}
				if method == http.MethodGet && (len(asset.body) == 0 || !bytes.Equal(w.Body.Bytes(), asset.body)) {
					t.Fatal("asset must contain exactly embedded bytes")
				}
				if method == http.MethodHead && w.Body.Len() != 0 {
					t.Fatal("HEAD wrote body")
				}
				if strings.Contains(w.Body.String(), "not-reflected") {
					t.Fatal("request secret reflected")
				}
			})
		}
	}
	for _, p := range []string{previewShellPrefix + "v2.js", previewShellPrefix + "../secret", "/other"} {
		w := httptest.NewRecorder()
		if servePreviewShellAsset(w, httptest.NewRequest(http.MethodGet, "http://example.test"+p, nil)) || w.Body.Len() != 0 || len(w.Header()) != 0 {
			t.Fatal("unknown asset route was handled")
		}
	}
}
