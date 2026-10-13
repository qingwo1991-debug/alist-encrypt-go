package encrypt

import "strings"

// canonicalMetadataDAVPath accepts an already-decoded object path (Request.URL.Path
// or the path selected by filename mapping). It must not unescape it a second
// time: a literal "%2f" filename is distinct from a directory separator.
func canonicalMetadataDAVPath(objectPath string) string {
	if objectPath == "" {
		return ""
	}
	if !strings.HasPrefix(objectPath, "/") {
		objectPath = "/" + objectPath
	}
	for _, prefix := range []string{"/dav2", "/d", "/p"} {
		if objectPath == prefix {
			return "/dav"
		}
		if strings.HasPrefix(objectPath, prefix+"/") {
			return "/dav/" + strings.TrimPrefix(objectPath, prefix+"/")
		}
	}
	if objectPath == "/dav" || strings.HasPrefix(objectPath, "/dav/") {
		return objectPath
	}
	return "/dav" + objectPath
}
