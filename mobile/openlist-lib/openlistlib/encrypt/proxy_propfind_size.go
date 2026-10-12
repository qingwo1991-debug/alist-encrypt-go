package encrypt

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// Only the exact single-object Depth:0 response may perform a header request.
// Directory listing remains memory-only, including on cold caches.
type propfindSizeProbe struct {
	ctx     context.Context
	target  string
	headers http.Header
	used    bool
}

const propfindResponseMaxBytes = 1 << 20

func (p *ProxyServer) processPropfindMetadata(body io.Reader, w io.Writer, ep *EncryptPath, budget *propfindRewriteBudget, probe *propfindSizeProbe) error {
	dec, enc := xml.NewDecoder(body), xml.NewEncoder(w)
	seen, closed := false, false
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if closed || (!seen && !strings.EqualFold(t.Name.Local, "multistatus")) {
				return errors.New("invalid PROPFIND metadata root")
			}
			seen = true
			if strings.EqualFold(t.Name.Local, "response") {
				tokens := []xml.Token{xml.CopyToken(t)}
				depth, bytes := 1, 0
				for depth > 0 {
					next, e := dec.Token()
					if e != nil {
						return e
					}
					switch n := next.(type) {
					case xml.StartElement:
						depth++
						bytes += len(n.Name.Local) + len(n.Name.Space)
						for _, a := range n.Attr {
							bytes += len(a.Value) + len(a.Name.Local) + len(a.Name.Space)
						}
					case xml.EndElement:
						depth--
					case xml.CharData:
						bytes += len(n)
					case xml.Comment:
						bytes += len(n)
					}
					if bytes > propfindResponseMaxBytes || len(tokens) >= 65536 {
						return errors.New("PROPFIND response exceeds bounded rewrite limit")
					}
					tokens = append(tokens, xml.CopyToken(next))
				}
				p.rewritePropfindEntry(tokens, ep, budget, probe)
				for _, next := range tokens {
					if err := enc.EncodeToken(next); err != nil {
						return err
					}
				}
				if err := enc.Flush(); err != nil {
					return err
				}
				continue
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "multistatus") {
				closed = true
			}
		case xml.CharData:
			if (!seen || closed) && strings.TrimSpace(string(t)) != "" {
				return errors.New("unexpected text outside PROPFIND metadata root")
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}
	if !seen || !closed {
		return errors.New("incomplete PROPFIND metadata response")
	}
	return enc.Flush()
}

func (p *ProxyServer) rewritePropfindEntry(tokens []xml.Token, ep *EncryptPath, budget *propfindRewriteBudget, probe *propfindSizeProbe) {
	href := ""
	size := int64(-1)
	collection := false
	var lengths []int
	// A failed property set is not metadata evidence; status can follow props.
	failedProp := make(map[int]bool)
	for i, token := range tokens {
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "propstat") {
			continue
		}
		end, depth := i+1, 1
		failed := false
		for ; end < len(tokens) && depth > 0; end++ {
			switch n := tokens[end].(type) {
			case xml.StartElement:
				depth++
				if strings.EqualFold(n.Name.Local, "status") && end+1 < len(tokens) {
					if cd, ok := tokens[end+1].(xml.CharData); ok {
						parts := strings.Fields(string(cd))
						if len(parts) > 1 && parts[1] != "200" {
							failed = true
						}
					}
				}
			case xml.EndElement:
				depth--
			}
		}
		if failed {
			for j := i; j < end; j++ {
				failedProp[j] = true
			}
		}
	}
	// Inspect the complete response before changing anything: href may follow size.
	for i, token := range tokens {
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if strings.EqualFold(start.Name.Local, "collection") {
			collection = true
		}
		if i+2 >= len(tokens) {
			continue
		}
		cd, ok := tokens[i+1].(xml.CharData)
		if !ok {
			continue
		}
		if _, ok := tokens[i+2].(xml.EndElement); !ok {
			continue
		}
		switch strings.ToLower(start.Name.Local) {
		case "href":
			if u, err := url.Parse(strings.TrimSpace(string(cd))); err == nil {
				href = u.Path
			}
		case "getcontentlength":
			if failedProp[i] {
				continue
			}
			if value, err := strconv.ParseInt(strings.TrimSpace(string(cd)), 10, 64); err == nil && value >= 0 {
				size = value
				lengths = append(lengths, i+1)
			}
		}
	}
	show := href
	if ep != nil && ep.EncName {
		for i, token := range tokens {
			start, ok := token.(xml.StartElement)
			if !ok || i+1 >= len(tokens) {
				continue
			}
			cd, ok := tokens[i+1].(xml.CharData)
			if !ok {
				continue
			}
			switch strings.ToLower(start.Name.Local) {
			case "href":
				if href == "" || collection || strings.HasSuffix(href, "/") {
					continue
				}
				name := path.Base(href)
				if path.Ext(name) != "" && !strings.HasPrefix(name, "orig_") {
					decoded := convertShowNameByRule(ep, name)
					if decoded != name && !strings.HasPrefix(decoded, "orig_") {
						show = path.Join(path.Dir(href), decoded)
						tokens[i+1] = xml.CharData((&url.URL{Path: show}).EscapedPath())
					}
				}
			case "displayname":
				name, err := url.PathUnescape(string(cd))
				if err != nil || collection || strings.HasPrefix(name, "orig_") || path.Ext(name) == "" {
					continue
				}
				decoded := convertShowNameByRule(ep, name)
				if decoded != name && !strings.HasPrefix(decoded, "orig_") {
					tokens[i+1] = xml.CharData(decoded)
				}
			}
		}
	}
	isDir := collection || strings.HasSuffix(href, "/") || size < 0
	// orig_ is an explicitly exposed original object, never a content-meta alias.
	eligible := ep != nil && ep.Enable && href != "" && !isDir && !strings.HasPrefix(path.Base(href), "orig_") && !strings.HasPrefix(path.Base(show), "orig_")
	var confirmed *FileInfo
	rejectInheritance := false
	if eligible {
		if info, ok := p.loadFileCacheInMem(href); ok && info != nil && !info.IsDir && info.CiphertextSize == size {
			if meta, valid := fileInfoContentMeta(info, EncryptionType(ep.EncType)); valid && propfindMetaSizeValid(meta, size) {
				copy := *info
				confirmed = &copy
			}
		}
		if probe != nil && !probe.used {
			target, err := url.Parse(probe.target)
			if err == nil && target.Path == href {
				probe.used = true
				// Depth:0 is authoritative: a failed fresh proof must not fall
				// back to a cached tuple, even when ciphertext sizes coincide.
				confirmed = nil
				ctx, cancel := context.WithTimeout(probe.ctx, p.propfindRetryTimeout())
				meta, ok := p.inspectLegacyContentMeta(ctx, probe.target, probe.headers, ep, size)
				cancel()
				if ok && propfindMetaSizeValid(meta, size) {
					confirmed = &FileInfo{Size: meta.PlainSize, CiphertextSize: meta.CiphertextSize, ContentVersion: meta.Version, HeaderLen: meta.HeaderLen, NonceField: cloneNonceField(meta.NonceField), ChunkSize: meta.ChunkSize, KDFIterations: meta.KDFIterations}
				} else {
					// Do not let list merging resurrect a failed proof or a
					// fresh V1/unenc conclusion as an older encrypted tuple.
					rejectInheritance = true
				}
			}
		}
	}
	if confirmed != nil {
		for _, i := range lengths {
			tokens[i] = xml.CharData(strconv.FormatInt(confirmed.Size, 10))
		}
	}
	if href != "" && (budget == nil || budget.entries < propdirHugeListEntries) {
		info := &FileInfo{Name: path.Base(href), Path: href, Size: max(size, 0), IsDir: isDir}
		if confirmed != nil {
			*info = *confirmed
			info.Name, info.Path = path.Base(href), href
		}
		// Mark the observed raw size separately so list merging can invalidate stale
		// encrypted tuples without losing the current upstream size.
		if confirmed == nil {
			info.CiphertextSize = max(size, 0)
		}
		p.storeFileCacheListProof(href, info, rejectInheritance)
		if show != "" && show != href {
			CacheNameMapping(path.Dir(show), path.Base(show), path.Base(href))
			copy := *info
			copy.Name, copy.Path = path.Base(show), show
			p.storeFileCacheListProof(show, &copy, rejectInheritance)
		}
	}
	if budget != nil && href != "" {
		budget.entries++
	}
}

func propfindMetaSizeValid(meta ContentMeta, raw int64) bool {
	if meta.CiphertextSize != raw || meta.PlainSize < 0 {
		return false
	}
	if meta.IsV3() {
		return ValidateV3ContentMeta(meta) == nil
	}
	return meta.IsV2() && meta.HeaderLen == ContentHeaderSize() && len(meta.NonceField) == 16 && meta.PlainSize > 0 && meta.PlainSize <= raw && raw-meta.PlainSize == meta.HeaderLen
}
