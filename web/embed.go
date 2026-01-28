package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed public/*
var staticFiles embed.FS

// GetFileSystem returns the embedded file system for static files
func GetFileSystem() http.FileSystem {
	fsys, err := fs.Sub(staticFiles, "public")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}
