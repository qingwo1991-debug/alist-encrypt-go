package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:public
var staticFiles embed.FS

// GetFileSystem returns the embedded file system for static files
func GetFileSystem() http.FileSystem {
	fsys, err := fs.Sub(staticFiles, "public")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}

// GetFileSystemWithPrefix returns the embedded file system without stripping "public" prefix
func GetFileSystemWithPrefix() http.FileSystem {
	return http.FS(staticFiles)
}
