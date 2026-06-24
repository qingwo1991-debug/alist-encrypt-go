//go:build !windows

package main

import (
	"fmt"
	"syscall"
)

// checkDiskSpace verifies that the output directory has enough free space.
// On platforms where Statfs fails, it silently succeeds (no false blocks).
func checkDiskSpace(outDir string, required int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(outDir, &stat); err != nil {
		return nil // can't check — don't block
	}
	avail := int64(stat.Bavail) * int64(stat.Bsize)
	if avail < required {
		return fmt.Errorf("insufficient disk space at %s: %s available, ~%s needed",
			outDir, formatBytes(avail), formatBytes(required))
	}
	return nil
}
