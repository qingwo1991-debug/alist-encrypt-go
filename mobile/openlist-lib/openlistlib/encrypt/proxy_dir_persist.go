package encrypt

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 目录列表“落盘元数据”：
//
// 手机端（openlist_mobile，无独立代理层）在远程 NAS 冷/抖动时，目录列表请求
// 会 404/502。这里在每次成功列出目录（depth=1）后，把该目录的文件名+大小写进
// 本地 localStore（SQLite），下次无论是重开 App 还是目录重建，都能先拿到“上次
// 见过的文件清单+尺寸”，从而在很多场景下免去逐文件探测/直接渲染历史数据。
//
// 约束（尊重手机端耗电）：
//   - 只写“已经在内存里的列表”本身的数据，绝不再发上游请求；
//   - 目录级 45s 冷却（复用 prefetchRecent），同目录短时间内不重复刷；
//   - 单目录条目封顶 webdavListPersistMaxEntries，避免超大目录一次写入过多。
//
// 相关：handleWebDAVLegacy 的 listDepth=="1" 成功分支、proxy_list_stale.go 的
// 后台刷新成功分支调用 maybePersistDirList。

const webdavListPersistMaxEntries = 120

type webdavListEntry struct {
	showPath string // /dav/ 明文展示路径
	name     string
	size     int64
	isDir    bool
}

// extractWebdavListEntries 从“已解密的 depth-1 PROPFIND 正文”中抽取每个条目的
// 展示路径与大小。逻辑与 processPropfindResponse 一致，但不重写内容、不写
// fileCache，只负责收集名字/大小/目录与否。
func extractWebdavListEntries(body []byte) []webdavListEntry {
	if len(body) == 0 {
		return nil
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	var entries []webdavListEntry
	var curHref string
	var curName string
	curSize := int64(-1)

	finish := func() {
		if curHref == "" {
			return
		}
		isDir := curSize <= 0
		size := curSize
		if isDir {
			size = 0
		}
		name := curName
		if name == "" {
			name = path.Base(curHref)
		}
		entries = append(entries, webdavListEntry{
			showPath: curHref,
			name:     name,
			size:     size,
			isDir:    isDir,
		})
		curHref = ""
		curName = ""
		curSize = -1
	}

	for {
		t, err := dec.Token()
		if err != nil {
			break
		}
		switch tok := t.(type) {
		case xml.StartElement:
			if strings.EqualFold(tok.Name.Local, "response") {
				finish()
			}
			if strings.EqualFold(tok.Name.Local, "href") {
				if cd, ok := nextCharData(dec); ok {
					if p, err := url.PathUnescape(string(cd)); err == nil {
						curHref = p
					} else {
						curHref = string(cd)
					}
				}
			}
			if strings.EqualFold(tok.Name.Local, "displayname") {
				if cd, ok := nextCharData(dec); ok {
					if n, err := url.PathUnescape(string(cd)); err == nil {
						curName = n
					} else {
						curName = string(cd)
					}
				}
			}
			if strings.EqualFold(tok.Name.Local, "getcontentlength") {
				if cd, ok := nextCharData(dec); ok {
					if v, err := strconv.ParseInt(strings.TrimSpace(string(cd)), 10, 64); err == nil {
						curSize = v
					}
				}
			}
		case xml.EndElement:
			if strings.EqualFold(tok.Name.Local, "response") {
				finish()
			}
		}
	}
	finish()
	return entries
}

func nextCharData(dec *xml.Decoder) ([]byte, bool) {
	for {
		t, err := dec.Token()
		if err != nil {
			return nil, false
		}
		if cd, ok := t.(xml.CharData); ok {
			return []byte(cd), true
		}
		if _, ok := t.(xml.StartElement); ok {
			return nil, false
		}
		if _, ok := t.(xml.EndElement); ok {
			return []byte{}, true
		}
	}
}

// maybePersistDirList 把成功列出的目录条目（名字+尺寸）落盘到本地 SQLite。
// 入口必须提供已经解密好的明文体（empty body 会被忽略）。只写已存在的数据，
// 不触发任何上游请求，目录级别由 cooldown 节流。
func (p *ProxyServer) maybePersistDirList(ctx context.Context, dirCacheKey string, body []byte) {
	if p == nil || p.localStore == nil || len(body) == 0 {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	if dirCacheKey == "" {
		return
	}
	if !p.shouldSchedulePrefetch("dirpersist:" + dirCacheKey) {
		return
	}

	entries := extractWebdavListEntries(body)
	if len(entries) == 0 {
		return
	}
	// 上限保护：超大目录只取前 N 个文件（优先视频/普通的非目录项）。
	if len(entries) > 2*webdavListPersistMaxEntries {
		entries = entries[:2*webdavListPersistMaxEntries]
	}

	providerURL := p.getAlistURL()
	now := time.Now()
	written := 0
	for _, e := range entries {
		if e.isDir || e.name == "" {
			continue
		}
		if written >= webdavListPersistMaxEntries {
			break
		}
		key, providerHost, originalPath, ok := p.localKeyFromURLs(providerURL, e.showPath)
		if !ok {
			continue
		}
		p.localStore.AddFullMeta(key, providerHost, originalPath, e.size, &prewarmMeta{
			name: e.name,
		}, now)
		written++
	}
	if written > 0 {
		log.Debugf("%s persisted dir list meta: dir=%s entries=%d/%d",
			internal.LogPrefix(ctx, internal.TagCache), dirCacheKey, written, len(entries))
	}
}
