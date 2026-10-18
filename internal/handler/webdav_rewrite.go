package handler

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// rewritePropfindBody decrypts filenames and adjusts confirmed getcontentlength in a
// single linear pass over a WebDAV multi-status XML body.
//
// Name rewriting remains linear. A second block-local pass marks unknown
// encrypted lengths unavailable rather than exposing ciphertext as plaintext.
//
// Recognized tag families (all case-variants D:/d:/no-prefix are supported):
//   - <displayname>: value decrypted with the password when EncName is set;
//   - <href>: /dav/ paths get the file name component decrypted, and the
//     display→encrypted mapping is recorded in the DAO;
//   - <getcontentlength>: reuse confirmed plaintext size when the current
//     response agrees with the observed container's ciphertext size;
//   - <response> / </response>: delimit blocks and reset the tracked path.
//
// Any other tag is copied through verbatim.
func (h *WebDAVHandler) rewritePropfindBody(body []byte, passwdInfo *config.PasswdInfo) []byte {
	allowLoose := h.cfg != nil && h.cfg.AlistServerSnapshot().AllowLooseDecode
	encryptNames := passwdInfo != nil && passwdInfo.EncName

	const (
		kindResp = iota // opening <response> (matched as "<...response>")
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
			if size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				if plain, ok := h.propfindPlainSize(activePath, size, passwdInfo); ok {
					out = strconv.FormatInt(plain, 10)
				}
			}
			b.WriteString(oi.open)
			b.WriteString(out)
			b.WriteString(oi.close)
		}

		pos = valueStart + relEnd + len(oi.close)
	}

	return h.hideUnknownPropfindLengths(b.Bytes(), body, passwdInfo)
}

// Unknown encrypted lengths are unavailable DAV properties, not ciphertext
// advertised as plaintext. Preserve collection properties and do not probe each
// member of a Depth:1 listing. A later Depth:0/GET confirms the container.
func (h *WebDAVHandler) hideUnknownPropfindLengths(body, original []byte, rule *config.PasswdInfo) []byte {
	if rule == nil || !rule.Enable {
		return body
	}
	// Token offsets preserve the upstream XML byte-for-byte except for the
	// length properties. Namespace prefixes and attributes are not fixed DAV
	// spellings; regexes limited to D: silently expose ciphertext for valid XML.
	entries := h.parsePropfindEntries(original)
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var out bytes.Buffer
	cursor, index := 0, -1
	inResponse, sawLength, known := false, false, false
	var plain int64
	for {
		start := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return body
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "response" && (t.Name.Space == "DAV:" || t.Name.Space == "") {
				index++
				inResponse, sawLength, known = index < len(entries), false, false
				if inResponse && !entries[index].IsDir {
					plain, known = h.propfindPlainSize(entries[index].Path, entries[index].Size, rule)
				}
			}
			if !inResponse || entries[index].IsDir || t.Name.Local != "getcontentlength" || (t.Name.Space != "DAV:" && t.Name.Space != "") {
				continue
			}
			openingEnd := int(decoder.InputOffset())
			var ignored string
			if err := decoder.DecodeElement(&ignored, &t); err != nil {
				return body
			}
			out.Write(body[cursor:start])
			if known {
				opening := body[start:openingEnd]
				if !bytes.HasSuffix(opening, []byte("/>")) {
					out.Write(opening)
					out.WriteString(strconv.FormatInt(plain, 10))
					end := int(decoder.InputOffset())
					closing := bytes.LastIndex(body[openingEnd:end], []byte("</"))
					if closing < 0 {
						return body
					}
					out.Write(body[openingEnd+closing : end])
				} else {
					out.WriteString(`<D:getcontentlength xmlns:D="DAV:">`)
					out.WriteString(strconv.FormatInt(plain, 10))
					out.WriteString(`</D:getcontentlength>`)
				}
			}
			cursor = int(decoder.InputOffset())
			sawLength = true
		case xml.EndElement:
			if t.Name.Local == "response" && inResponse && (t.Name.Space == "DAV:" || t.Name.Space == "") {
				if sawLength && !known && !entries[index].IsDir {
					out.Write(body[cursor:start])
					out.WriteString(`<D:propstat xmlns:D="DAV:"><D:prop><D:getcontentlength/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>`)
					cursor = start
				}
				inResponse = false
			}
		}
	}
	out.Write(body[cursor:])
	return out.Bytes()
}

// A DAV listing reports transport size, not container geometry. Only reuse an
// observed container when its ciphertext length agrees; never infer a version,
// nonce, chunk size or KDF from a directory entry (and never subtract twice).
func (h *WebDAVHandler) propfindPlainSize(rawPath string, reported int64, rules ...*config.PasswdInfo) (int64, bool) {
	if h.fileDAO == nil || rawPath == "" {
		return 0, false
	}
	fi, ok := h.fileDAO.Get(rawPath)
	if !ok || fi == nil || fi.IsDir || fi.Size < 0 {
		return 0, false
	}
	if fi.ContentVersion < encryption.ContentVersionV1 || fi.ContentVersion > encryption.ContentVersionV3 {
		return 0, false
	}
	if h.cfg != nil && h.cfg.AlistServerSnapshot().PlaybackProfile == config.PlaybackProfileTrustedLocal {
		if repo, managed := h.fileDAO.(playbackCacheRepository); managed {
			var rule *config.PasswdInfo
			if len(rules) > 0 {
				rule = rules[0]
			}
			identity := playbackIdentity(h.cfg, h.cfg.GetAlistURL(), rawPath, rule, nil)
			confirmed, hit := repo.GetConfirmedPlayback(identity)
			if !hit || confirmed == nil || confirmed.EncryptedPath != rawPath || confirmed.CiphertextSize != reported {
				return 0, false
			}
			return confirmed.Size, true
		}
	}
	if fi.CiphertextSize > 0 && reported == fi.CiphertextSize {
		return fi.Size, true
	}
	return 0, false
}
