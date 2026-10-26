package handler

import (
	"bytes"
	_ "embed"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

	"golang.org/x/net/html"
)

// These assets are deliberately independent of the upstream's hashed bundles.
// They present UI only: metadata, authorization and media requests stay upstream.
//
//go:embed assets/preview-shell.js
var previewShellJS []byte

//go:embed assets/preview-shell.css
var previewShellCSS []byte

const previewShellPrefix = "/__aeg/preview-shell/"

func servePreviewShellAsset(w http.ResponseWriter, r *http.Request) bool {
	var body []byte
	var contentType string
	switch r.URL.Path {
	case previewShellPrefix + "v1.js":
		body, contentType = previewShellJS, "text/javascript; charset=utf-8"
	case previewShellPrefix + "v1.css":
		body, contentType = previewShellCSS, "text/css; charset=utf-8"
	default:
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}

// This is deliberately only a request-side candidate check. It must never be
// used instead of the response and structural HTML checks below.
func isPreviewShellDocumentRequest(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodGet ||
		len(r.Header.Values("Range")) != 0 {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return false
	}
	if accept := strings.ToLower(r.Header.Get("Accept")); accept != "" &&
		!strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
		return false
	}
	p := strings.ToLower(path.Clean("/" + r.URL.Path))
	for _, prefix := range []string{"/api", "/enc-api", "/enc", "/d", "/p", "/dav", "/images", "/assets", "/download", "/downloads", "/admin", "/__aeg"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return false
		}
	}
	return !strings.HasPrefix(p, "/@") && !hasPreviewShellNoTransform(r.Header)
}

func hasPreviewShellNoTransform(header http.Header) bool {
	for _, value := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, _, _ := strings.Cut(strings.TrimSpace(directive), "=")
			if strings.EqualFold(name, "no-transform") {
				return true
			}
		}
	}
	return false
}

// Only transform a positively identified OpenList SPA document. Explicit CSP
// (including report-only and meta policies) is conservatively left untouched;
// this helper never adds a nonce, changes a policy, or relaxes a directive.
func injectPreviewShell(r *http.Request, resp *http.Response, body []byte) ([]byte, bool) {
	if !isPreviewShellDocumentRequest(r) || resp == nil || resp.StatusCode != http.StatusOK {
		return body, false
	}
	h := resp.Header
	contentTypes := h.Values("Content-Type")
	if len(contentTypes) != 1 {
		return body, false
	}
	mediaType, params, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "text/html" {
		return body, false
	}
	if charset := strings.ToLower(params["charset"]); charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return body, false
	}
	for _, name := range []string{"Content-Disposition", "Content-Security-Policy", "Content-Security-Policy-Report-Only", "Content-Range"} {
		if len(h.Values(name)) != 0 {
			return body, false
		}
	}
	for _, encoding := range h.Values("Content-Encoding") {
		if !strings.EqualFold(strings.TrimSpace(encoding), "identity") {
			return body, false
		}
	}
	if hasPreviewShellNoTransform(h) {
		return body, false
	}
	end, ok := previewShellDocumentHeadEnd(body)
	if !ok {
		return body, false
	}
	tags := []byte(`<link rel="stylesheet" href="` + previewShellPrefix + `v1.css"><script defer src="` + previewShellPrefix + `v1.js"></script>`)
	out := make([]byte, 0, len(body)+len(tags))
	out = append(out, body[:end]...)
	out = append(out, tags...)
	out = append(out, body[end:]...)
	return out, true
}

func previewShellAttrs(token html.Token) (map[string]string, bool) {
	attrs := make(map[string]string, len(token.Attr))
	for _, attr := range token.Attr {
		if _, exists := attrs[attr.Key]; exists {
			return nil, false
		}
		attrs[attr.Key] = attr.Val
	}
	return attrs, true
}

// Token positions refer to the original bytes: do not serialize the document,
// which could otherwise rewrite arbitrary upstream markup or inline scripts.
func previewShellDocumentHeadEnd(body []byte) (int, bool) {
	z := html.NewTokenizer(bytes.NewReader(body))
	offset, headEnd, roots := 0, -1, 0
	inHead, seenHead, inBody, seenBody, doctype := false, false, false, false, false
	bootstrap, module := false, false
	inlineScript := false
	for {
		tt := z.Next()
		start := offset
		offset += len(z.Raw())
		if tt == html.ErrorToken {
			return headEnd, z.Err() == io.EOF && headEnd >= 0 && doctype && seenHead && seenBody && roots == 1 && bootstrap && module && !inHead && !inBody
		}
		token := z.Token()
		switch tt {
		case html.DoctypeToken:
			if doctype || !strings.EqualFold(token.Data, "html") {
				return -1, false
			}
			doctype = true
		case html.StartTagToken, html.SelfClosingTagToken:
			attrs, ok := previewShellAttrs(token)
			if !ok {
				return -1, false
			}
			// A base URL changes the origin of otherwise root-relative assets.
			// Templates/foreign content cannot supply our app's real mount.
			switch token.Data {
			case "base", "template", "svg", "math", "iframe", "frameset":
				return -1, false
			case "head":
				if seenHead || seenBody {
					return -1, false
				}
				inHead, seenHead = true, true
			case "body":
				if seenBody || inHead || headEnd < 0 {
					return -1, false
				}
				inBody, seenBody = true, true
			case "meta":
				policy := strings.ToLower(strings.TrimSpace(attrs["http-equiv"]))
				if policy == "content-security-policy" || policy == "content-security-policy-report-only" || policy == "refresh" {
					return -1, false
				}
			case "div":
				if attrs["id"] == "root" {
					if !inBody {
						return -1, false
					}
					roots++
				}
			case "script":
				inlineScript = inHead && attrs["src"] == "" && (attrs["type"] == "" || attrs["type"] == "text/javascript" || attrs["type"] == "module")
				if inHead && strings.EqualFold(attrs["type"], "module") {
					module = true
				}
			}
			for _, name := range []string{"src", "href"} {
				if strings.Contains(attrs[name], previewShellPrefix) {
					return -1, false
				}
			}
		case html.TextToken:
			if inlineScript && strings.Contains(token.Data, "window.OPENLIST_CONFIG") && strings.Contains(token.Data, "window.__dynamic_base__") && strings.Contains(token.Data, "=") {
				bootstrap = true
			}
		case html.EndTagToken:
			switch token.Data {
			case "head":
				if !inHead || headEnd >= 0 {
					return -1, false
				}
				headEnd, inHead = start, false
			case "body":
				inBody = false
			case "script":
				inlineScript = false
			}
		}
	}
}
