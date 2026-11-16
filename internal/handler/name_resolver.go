package handler

import (
	"net/url"
	"path"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// nameResolver is the single entry point for display-name -> upstream-name
// resolution on mutating operations (fs/remove, fs/move, fs/copy, fs/rename,
// WebDAV DELETE/MOVE/COPY). Every caller shares the same decision chain —
// cache mapping, cached file info, encrypted-name passthrough, orig_
// stripping, upstream existence probe, then filename encryption — so the
// plaintext/encrypted/directory edge cases cannot drift apart per endpoint.
//
// Probes are injected by the caller because API handlers and WebDAV reach
// upstream through different clients; the decision logic itself lives here.
type nameResolver struct {
	fileDAO ports.FileRepository
	passwd  *config.PasswdInfo
}

func newNameResolver(fileDAO ports.FileRepository, passwdInfo *config.PasswdInfo) *nameResolver {
	return &nameResolver{fileDAO: fileDAO, passwd: passwdInfo}
}

// upstreamBasename maps one display basename under dirPath to the single
// upstream basename that mutating APIs must send. Cached mappings win;
// otherwise plaintext directories/files keep their spelling and only names
// with no upstream object are filename-encrypted. probe reports whether the
// display spelling exists upstream (batch callers substitute one directory
// listing for N per-name fs/get probes).
func (nr *nameResolver) upstreamBasename(dirPath, name string, probe func() bool) string {
	displayPath := path.Join(dirPath, name)
	if nr.fileDAO != nil {
		if encPath, ok := nr.fileDAO.GetEncPath(displayPath); ok {
			return path.Base(encPath)
		}
	}

	cachedRemoveName := func(fileInfo *dao.FileInfo) (string, bool) {
		if fileInfo == nil {
			return "", false
		}
		if fileInfo.IsDir {
			if fileInfo.Path != "" {
				return path.Base(fileInfo.Path), true
			}
			return name, true
		}
		if fileInfo.EncryptedPath != "" && fileInfo.EncryptedPath != displayPath {
			return path.Base(fileInfo.EncryptedPath), true
		}
		return "", false
	}
	if nr.fileDAO != nil {
		for _, cacheKey := range []string{displayPath, url.QueryEscape(displayPath)} {
			if fileInfo, ok := nr.fileDAO.Get(cacheKey); ok {
				if resolved, hit := cachedRemoveName(fileInfo); hit {
					return resolved
				}
			}
		}
	}

	if nr.passwd != nil && nr.passwd.EncName {
		converter := encryption.NewFileNameConverter(nr.passwd.Password, nr.passwd.EncType, nr.passwd.EncSuffix)
		fileName := path.Base(name)
		encBase := strings.TrimSuffix(fileName, path.Ext(fileName))
		if converter.DecryptFileName(encBase) != "" {
			return name
		}
		if strings.HasPrefix(fileName, encryption.OrigPrefix) {
			return strings.TrimPrefix(fileName, encryption.OrigPrefix)
		}
		// Directories and unencrypted files keep their upstream spelling. Only
		// names with no upstream object under the display spelling are encrypted.
		if probe() {
			return name
		}
		return converter.ToRealName(name)
	}

	return name
}

// sourcePath maps a full display path to its upstream path and reports
// whether the object is a directory. Directory display names are never
// filename-encrypted, so cached or probed directories keep their spelling
// instead of being run through ToRealName. probe reports (exists, isDir) for
// the display spelling upstream.
func (nr *nameResolver) sourcePath(displayPath string, probe func() (bool, bool)) (string, bool) {
	if nr.fileDAO != nil {
		if encPath, ok := nr.fileDAO.GetEncPath(displayPath); ok && strings.TrimSpace(encPath) != "" {
			if info, ok := nr.fileDAO.Get(displayPath); ok && info != nil {
				return encPath, info.IsDir
			}
			if info, ok := nr.fileDAO.Get(url.QueryEscape(displayPath)); ok && info != nil {
				return encPath, info.IsDir
			}
			return encPath, false
		}
	}

	if nr.fileDAO != nil {
		for _, cacheKey := range []string{displayPath, url.QueryEscape(displayPath)} {
			if info, ok := nr.fileDAO.Get(cacheKey); ok && info != nil {
				if info.IsDir {
					if info.EncryptedPath != "" && info.EncryptedPath != displayPath {
						return info.EncryptedPath, true
					}
					return displayPath, true
				}
				if info.EncryptedPath != "" && info.EncryptedPath != displayPath {
					return info.EncryptedPath, false
				}
				return displayPath, false
			}
		}
	}

	if nr.passwd == nil || !nr.passwd.EncName {
		return displayPath, false
	}
	converter := encryption.NewFileNameConverter(nr.passwd.Password, nr.passwd.EncType, nr.passwd.EncSuffix)
	fileName := path.Base(displayPath)
	encBase := strings.TrimSuffix(fileName, path.Ext(fileName))
	if converter.DecryptFileName(encBase) != "" {
		return displayPath, false
	}
	if strings.HasPrefix(fileName, encryption.OrigPrefix) {
		// Keep the stripped spelling literal: "." / ".." must reach the
		// mutation-name validation instead of being cleaned away by path.Join.
		return path.Dir(displayPath) + "/" + strings.TrimPrefix(fileName, encryption.OrigPrefix), false
	}
	if exists, isDir := probe(); exists {
		return displayPath, isDir
	}
	return path.Join(path.Dir(displayPath), converter.ToRealName(fileName)), false
}

// destinationPath maps a full display destination path (WebDAV MOVE/COPY
// Destination, and any create-style target) to the upstream path the client
// asked for. Directory sources keep their literal spelling; file destinations
// resolve through cache, encrypted-name passthrough, orig_ stripping, and
// finally filename encryption — the same edge cases as sourcePath, minus the
// existence probe (a destination usually does not exist yet).
func (nr *nameResolver) destinationPath(displayPath string, sourceIsDir bool) string {
	if nr.passwd == nil || !nr.passwd.EncName || sourceIsDir {
		return displayPath
	}
	if nr.fileDAO != nil {
		if encPath, ok := nr.fileDAO.GetEncPath(displayPath); ok && strings.TrimSpace(encPath) != "" {
			return encPath
		}
		for _, cacheKey := range []string{displayPath, url.QueryEscape(displayPath)} {
			if info, ok := nr.fileDAO.Get(cacheKey); ok && info != nil {
				if info.EncryptedPath != "" && info.EncryptedPath != displayPath {
					return info.EncryptedPath
				}
				return displayPath
			}
		}
	}
	converter := encryption.NewFileNameConverter(nr.passwd.Password, nr.passwd.EncType, nr.passwd.EncSuffix)
	fileName := path.Base(displayPath)
	encBase := strings.TrimSuffix(fileName, path.Ext(fileName))
	if converter.DecryptFileName(encBase) != "" {
		return displayPath
	}
	return path.Join(path.Dir(displayPath), converter.ToRealName(fileName))
}
