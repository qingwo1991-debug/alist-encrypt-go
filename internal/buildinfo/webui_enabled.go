//go:build !noembedwebui

package buildinfo

func EmbeddedWebUI() bool {
	return true
}

func ManagementMode() string {
	return "embedded_web"
}
