package handler

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
)

// ---- old decryptPropfindResponse (git HEAD) as a pure function ----
func oldDecryptPropfind(body []byte, password, encType, encSuffix string, allowLoose bool) []byte {
	type tagPair struct {
		start, end string
		kind       int
	}
	tags := []tagPair{
		{`<D:displayname>`, `</D:displayname>`, 0},
		{`<d:displayname>`, `</d:displayname>`, 0},
		{`<displayname>`, `</displayname>`, 0},
		{`<D:href>`, `</D:href>`, 1},
		{`<d:href>`, `</d:href>`, 1},
		{`<href>`, `</href>`, 1},
		{`<D:getcontentlength>`, `</D:getcontentlength>`, 2},
		{`<d:getcontentlength>`, `</d:getcontentlength>`, 2},
		{`<getcontentlength>`, `</getcontentlength>`, 2},
	}
	headerSize := encryption.ContentHeaderSize()
	searchPos := 0
	var out bytes.Buffer
	out.Grow(len(body))
	sb := string(body)
	for searchPos < len(body) {
		bestStart, bestEnd, bestKind := -1, -1, -1
		var bestStartTag, bestEndTag string
		for _, t := range tags {
			if t.kind == 2 && headerSize <= 0 {
				continue
			}
			idx := strings.Index(sb[searchPos:], t.start)
			if idx == -1 {
				continue
			}
			absStart := searchPos + idx
			if bestStart != -1 && absStart >= bestStart {
				continue
			}
			endIdx := strings.Index(sb[absStart+len(t.start):], t.end)
			if endIdx == -1 {
				continue
			}
			bestStart, bestEnd, bestKind = absStart, absStart+len(t.start)+endIdx, t.kind
			bestStartTag, bestEndTag = t.start, t.end
		}
		if bestStart == -1 {
			out.WriteString(sb[searchPos:])
			break
		}
		out.WriteString(sb[searchPos:bestStart])
		out.WriteString(bestStartTag)
		content := sb[bestStart+len(bestStartTag) : bestEnd]
		switch bestKind {
		case 0:
			if content != "" && content != "/" {
				d := encryption.ConvertShowNameWithSuffixOptions(password, encType, content, encSuffix, allowLoose)
				if d != "" && d != content {
					out.WriteString(d)
					out.WriteString(bestEndTag)
					searchPos = bestEnd + len(bestEndTag)
					continue
				}
			}
			out.WriteString(content)
			out.WriteString(bestEndTag)
		case 1:
			if strings.HasPrefix(content, "/dav/") {
				davPath := strings.TrimPrefix(content, "/dav")
				decodedPath := unescapePath(davPath)
				if decodedPath != "/" && decodedPath != "" {
					fileName := path.Base(decodedPath)
					if fileName != "" && fileName != "/" && fileName != "." {
						d := encryption.ConvertShowNameWithSuffixOptions(password, encType, fileName, encSuffix, allowLoose)
						if d != "" && !encryption.IsOriginalFile(d) && d != fileName {
							origName := path.Base(content)
							decHref := strings.TrimSuffix(content, origName) + d
							out.WriteString(decHref)
							out.WriteString(bestEndTag)
							searchPos = bestEnd + len(bestEndTag)
							continue
						}
					}
				}
			}
			out.WriteString(content)
			out.WriteString(bestEndTag)
		case 2:
			out.WriteString(content)
			out.WriteString(bestEndTag)
		}
		searchPos = bestEnd + len(bestEndTag)
	}
	return out.Bytes()
}

func unescapePath(s string) string {
	dec, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return dec
}

// ---- old adjustPropfindContentLengthForV2 (git HEAD) as a pure function ----
func oldAdjustPropfind(xmlStr string, isV2 func(path string) bool) string {
	headerSize := encryption.ContentHeaderSize()
	if headerSize <= 0 {
		return xmlStr
	}
	contentLengthVariants := [][2]string{
		{"<D:getcontentlength>", "</D:getcontentlength>"},
		{"<d:getcontentlength>", "</d:getcontentlength>"},
		{"<getcontentlength>", "</getcontentlength>"},
	}
	hrefVariants := [][2]string{
		{"<D:href>", "</D:href>"},
		{"<d:href>", "</d:href>"},
		{"<href>", "</href>"},
	}
	result := xmlStr
	searchPos := 0
	for {
		respStart := -1
		for _, prefix := range []string{"<D:response>", "<d:response>", "<response>"} {
			idx := strings.Index(result[searchPos:], prefix)
			if idx == -1 {
				continue
			}
			absIdx := searchPos + idx
			if respStart == -1 || absIdx < respStart {
				respStart = absIdx
			}
		}
		if respStart == -1 {
			break
		}
		respEnd := -1
		for _, suffix := range []string{"</D:response>", "</d:response>", "</response>"} {
			idx := strings.Index(result[respStart:], suffix)
			if idx == -1 {
				continue
			}
			absIdx := respStart + idx + len(suffix)
			if respEnd == -1 || absIdx < respEnd {
				respEnd = absIdx
			}
		}
		if respEnd == -1 {
			break
		}
		block := result[respStart:respEnd]
		filePath := ""
		for _, hv := range hrefVariants {
			idx := strings.Index(block, hv[0])
			if idx == -1 {
				continue
			}
			hrefStart := idx + len(hv[0])
			rest := block[hrefStart:]
			hrefEnd := strings.Index(rest, hv[1])
			if hrefEnd == -1 {
				continue
			}
			href := rest[:hrefEnd]
			hrefPath := strings.TrimPrefix(href, "/dav")
			if decoded, err := url.PathUnescape(hrefPath); err == nil {
				filePath = decoded
			} else {
				filePath = hrefPath
			}
			break
		}
		for _, variant := range contentLengthVariants {
			idx := strings.Index(block, variant[0])
			if idx == -1 {
				continue
			}
			valStart := idx + len(variant[0])
			rest := block[valStart:]
			valEnd := strings.Index(rest, variant[1])
			if valEnd == -1 {
				continue
			}
			valEnd += valStart
			valStr := strings.TrimSpace(block[valStart:valEnd])
			size, err := strconv.ParseInt(valStr, 10, 64)
			if err != nil || size <= headerSize {
				continue
			}
			if !isV2(filePath) {
				continue
			}
			newValStr := strconv.FormatInt(size-headerSize, 10)
			absValStart := respStart + valStart
			absValEnd := respStart + valEnd
			result = result[:absValStart] + newValStr + result[absValEnd:]
			break
		}
		searchPos = respEnd
	}
	return result
}

func TestDecryptPropfindO1MatchesOldAndFast(t *testing.T) {
	body, err := os.ReadFile("/tmp/prop_direct.html")
	if err != nil {
		t.Skip("no /tmp/prop_direct.html")
	}
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := "aesctr"
	encSuffix := ".bin"

	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h := newProbeTestHandler(t, backend.URL)
	pi := &config.PasswdInfo{Password: password, EncType: encType, EncSuffix: encSuffix}

	// warm caches
	_ = encryption.ConvertShowNameWithSuffixOptions(password, encType, "warm", encSuffix, false)

	tr := time.Now()
	newOut := h.decryptPropfindResponse(body, pi)
	newD := time.Since(tr)

	tr = time.Now()
	oldOut := oldDecryptPropfind(body, password, encType, encSuffix, false)
	oldD := time.Since(tr)

	t.Logf("NEW decryptPropfind: %v (outLen=%d)", newD, len(newOut))
	t.Logf("OLD decryptPropfind: %v (outLen=%d)", oldD, len(oldOut))

	if !bytes.Equal(newOut, oldOut) {
		n := len(newOut)
		if len(oldOut) < n {
			n = len(oldOut)
		}
		for i := 0; i < n; i++ {
			if newOut[i] != oldOut[i] {
				t.Fatalf("decrypt output mismatch at %d: new=%q old=%q", i, newOut[i:i+120], oldOut[i:i+120])
			}
		}
		t.Fatalf("decrypt length mismatch: new=%d old=%d", len(newOut), len(oldOut))
	}

	// --- adjust ---
	// The new adjust consults h.fileDAO for ContentVersion==2. Prefill V2=2 for
	// every href path so it matches old's all-is-V2 predicate.
	prefillV2(t, h, string(newOut))
	allV2 := func(string) bool { return true }
	tr = time.Now()
	newAdj := h.adjustPropfindContentLengthForV2(string(newOut))
	newAdjD := time.Since(tr)
	tr = time.Now()
	oldAdj := oldAdjustPropfind(string(newOut), allV2)
	oldAdjD := time.Since(tr)
	t.Logf("NEW adjust: %v", newAdjD)
	t.Logf("OLD adjust: %v", oldAdjD)
	if newAdj != oldAdj {
		n := len(newAdj)
		if len(oldAdj) < n {
			n = len(oldAdj)
		}
		for i := 0; i < n; i++ {
			if newAdj[i] != oldAdj[i] {
				t.Fatalf("adjust mismatch at %d: new=%q old=%q", i, newAdj[i:i+100], oldAdj[i:i+100])
			}
		}
		t.Fatalf("adjust length mismatch: new=%d old=%d", len(newAdj), len(oldAdj))
	}
}

// TestRewritePropfindBodyMatchesOldBytes is the decisive whole-body equivalence
// check: for the real 联通 encrypt PROPFIND XML it compares the new single-pass
// rewritePropfindBody (decrypt + V2-size adjust in one pass) against the old
// two-pass sequence (decryptPropfindResponse then adjustPropfindContentLengthForV2),
// on exactly the state the old path used (no DAO prefill so adjust consults DAO).
func TestRewritePropfindBodyMatchesOldBytesRewrite(t *testing.T) {
	body, err := os.ReadFile("/tmp/prop_direct.html")
	if err != nil {
		t.Skip("no /tmp/prop_direct.html")
	}
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := "aesctr"
	encSuffix := ".bin"

	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h := newProbeTestHandler(t, backend.URL)
	pi := &config.PasswdInfo{Password: password, EncType: encType, EncSuffix: encSuffix, EncName: true}

	_ = encryption.ConvertShowNameWithSuffixOptions(password, encType, "warm", encSuffix, false)

	tr := time.Now()
	merged := h.rewritePropfindBody(body, pi)
	mergedD := time.Since(tr)

	tr = time.Now()
	twoPass := h.decryptPropfindResponse(body, pi)
	twoPass = []byte(h.adjustPropfindContentLengthForV2(string(twoPass)))
	twoPassD := time.Since(tr)

	t.Logf("NEW rewritePropfindBody: %v (outLen=%d)", mergedD, len(merged))
	t.Logf("OLD two-pass          : %v (outLen=%d)", twoPassD, len(twoPass))

	if !bytes.Equal(merged, twoPass) {
		n := len(merged)
		if len(twoPass) < n {
			n = len(twoPass)
		}
		for i := 0; i < n; i++ {
			if merged[i] != twoPass[i] {
				t.Fatalf("rewrite mismatch at %d:\nnew=%q\nold=%q", i, merged[i:i+120], twoPass[i:i+120])
			}
		}
		t.Fatalf("rewrite length mismatch: new=%d old=%d", len(merged), len(twoPass))
	}
}

func prefillV2(t *testing.T, h *WebDAVHandler, xml string) {
	// extract every href path and set as V2 file
	re := regexp.MustCompile(`<D:href>(/dav/[^<]+)</D:href>`)
	for _, m := range re.FindAllStringSubmatch(xml, -1) {
		href := m[1]
		if strings.HasSuffix(href, "/") {
			continue
		}
		dp := strings.TrimPrefix(href, "/dav")
		dec, err := url.PathUnescape(dp)
		if err != nil {
			dec = dp
		}
		if h.fileDAO == nil {
			t.Fatal("fileDAO nil")
		}
		if err := h.fileDAO.Set(&dao.FileInfo{Path: dec, Name: path.Base(dec), Size: 100, IsDir: false, ContentVersion: 2}); err != nil {
			t.Fatal(err)
		}
	}
}
