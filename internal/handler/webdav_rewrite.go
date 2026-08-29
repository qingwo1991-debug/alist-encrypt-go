package handler

import (
	"bytes"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

// rewritePropfindBody decrypts filenames and adjusts V2 getcontentlength in a
// single linear pass over a WebDAV multi-status XML body.
//
// It replaces the old two-pass sequence (decryptPropfindResponse then
// adjustPropfindContentLengthForV2) and is byte-for-byte output-equivalent to
// it, while walking the document only once. For very large listings (tens of
// thousands of entries) this keeps the whole rewrite O(input) with no repeated
// whole-document scans.
//
// Recognized tag families (all case-variants D:/d:/no-prefix are supported):
//   - <displayname>: value decrypted with the password when EncName is set;
//   - <href>: /dav/ paths get the file name component decrypted, and the
//     display→encrypted mapping is recorded in the DAO;
//   - <getcontentlength>: for the file in the current <response> block, if the
//     cached metadata confirms ContentVersion==2, subtract the header size;
//   - <response> / </response>: delimit blocks and reset the tracked path.
//
// Any other tag is copied through verbatim.
func (h *WebDAVHandler) rewritePropfindBody(body []byte, passwdInfo *config.PasswdInfo) []byte {
	headerSize := encryption.ContentHeaderSize()
	allowLoose := h.cfg != nil && h.cfg.AlistServerSnapshot().AllowLooseDecode
	encryptNames := passwdInfo != nil && passwdInfo.EncName

	const (
		kindResp  = iota // opening <response> (matched as "<...response>")
		kindDisplay
		kindHref
		kindLength
	)
	type opener struct {
		open, close string
		kind        int
	}
	openers := []opener{
		{"<D:response>", "", kindResp},
		{"<d:response>", "", kindResp},
		{"<response>", "", kindResp},
		{"<D:displayname>", "</D:displayname>", kindDisplay},
		{"<d:displayname>", "</d:displayname>", kindDisplay},
		{"<displayname>", "</displayname>", kindDisplay},
		{"<D:href>", "</D:href>", kindHref},
		{"<d:href>", "</d:href>", kindHref},
		{"<href>", "</href>", kindHref},
		{"<D:getcontentlength>", "</D:getcontentlength>", kindLength},
		{"<d:getcontentlength>", "</d:getcontentlength>", kindLength},
		{"<getcontentlength>", "</getcontentlength>", kindLength},
	}

	var b bytes.Buffer
	b.Grow(len(body))
	pos := 0
	n := len(body)

	// encrypted (real) path of the file in the current <response> block
	activePath := ""

	for pos < n {
		ltRel := bytes.IndexByte(body[pos:], '<')
		if ltRel == -1 {
			b.Write(body[pos:])
			break
		}
		lt := pos + ltRel
		if lt > pos {
			b.Write(body[pos:lt])
		}
		tail := body[lt:]

		// <D:response>, <d:response>, <response> handled first (block delimiters).
		// Written with explicit full-tag slices rather than len("<response>") so
		// the D:-prefixed variants are not truncated.
		switch {
		case bytes.HasPrefix(tail, []byte("<D:response>")):
			activePath = ""
			b.WriteString("<D:response>")
			pos = lt + len("<D:response>")
			continue
		case bytes.HasPrefix(tail, []byte("<d:response>")):
			activePath = ""
			b.WriteString("<d:response>")
			pos = lt + len("<d:response>")
			continue
		case bytes.HasPrefix(tail, []byte("<response>")):
			activePath = ""
			b.WriteString("<response>")
			pos = lt + len("<response>")
			continue
		case bytes.HasPrefix(tail, []byte("</D:response>")):
			b.WriteString("</D:response>")
			pos = lt + len("</D:response>")
			continue
		case bytes.HasPrefix(tail, []byte("</d:response>")):
			b.WriteString("</d:response>")
			pos = lt + len("</d:response>")
			continue
		case bytes.HasPrefix(tail, []byte("</response>")):
			b.WriteString("</response>")
			pos = lt + len("</response>")
			continue
		}

		// find a value-bearing opener among displayname/href/getcontentlength
		matched := false
		var oi opener
		for _, op := range openers {
			if bytes.HasPrefix(tail, []byte(op.open)) {
				oi = op
				matched = true
				break
			}
		}
		if !matched {
			b.WriteByte('<')
			pos = lt + 1
			continue
		}

		valueStart := lt + len(oi.open)
		relEnd := bytes.Index(body[valueStart:], []byte(oi.close))
		if relEnd == -1 {
			b.WriteString(string(body[lt:]))
			break
		}
		value := string(body[valueStart : valueStart+relEnd])

		switch oi.kind {
		case kindDisplay:
			dec := value
			if encryptNames && value != "" && value != "/" {
				if d := encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, value, passwdInfo.EncSuffix, allowLoose); d != "" {
					dec = d
				}
			}
			b.WriteString(oi.open)
			b.WriteString(dec)
			b.WriteString(oi.close)

		case kindHref:
			rewritten := value
			if strings.HasPrefix(value, "/dav/") {
				davPath := strings.TrimPrefix(value, "/dav")
				decodedPath, err := url.PathUnescape(davPath)
				if err != nil {
					decodedPath = davPath
				}
				if decodedPath != "" && decodedPath != "/" {
					fileName := path.Base(decodedPath)
					if fileName != "" && fileName != "/" && fileName != "." {
						decName := ""
						if encryptNames {
							decName = encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, fileName, passwdInfo.EncSuffix, allowLoose)
						}
						if decName != "" && !encryption.IsOriginalFile(decName) && decName != fileName {
							displayPath := path.Dir(decodedPath) + "/" + decName
							h.fileDAO.SetEncPathMapping(displayPath, decodedPath)
							if fileInfo, ok := h.fileDAO.Get(decodedPath); ok {
								h.fileDAO.SetEncPathMappingWithInfo(displayPath, decodedPath, decName, fileInfo.Size, fileInfo.IsDir)
							}
							origName := path.Base(value)
							rewritten = strings.TrimSuffix(value, origName) + decName
						}
					}
				}
			}
			b.WriteString(oi.open)
			b.WriteString(rewritten)
			b.WriteString(oi.close)
			// set active path for this response block so getcontentlength can look it up
			if strings.HasPrefix(value, "/dav/") {
				dp := strings.TrimPrefix(value, "/dav")
				if dec, err := url.PathUnescape(dp); err == nil {
					activePath = dec
				} else {
					activePath = dp
				}
			}

		case kindLength:
			out := value
			if headerSize > 0 && activePath != "" && h.fileDAO != nil {
				if fi, ok := h.fileDAO.Get(activePath); ok && fi != nil && fi.ContentVersion == 2 {
					if size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && size > headerSize {
						out = strconv.FormatInt(size-headerSize, 10)
					}
				}
			}
			b.WriteString(oi.open)
			b.WriteString(out)
			b.WriteString(oi.close)
		}

		pos = valueStart + relEnd + len(oi.close)
	}

	return b.Bytes()
}