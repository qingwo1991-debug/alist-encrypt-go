//go:build noembedwebui

package buildinfo

func EmbeddedWebUI() bool {
	return false
}

func ManagementMode() string {
	return "external_app"
}
