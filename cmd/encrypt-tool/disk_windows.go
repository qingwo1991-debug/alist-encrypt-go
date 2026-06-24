//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// checkDiskSpace verifies that the output directory has enough free space.
// Uses GetDiskFreeSpaceEx on Windows.
func checkDiskSpace(outDir string, required int64) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")

	var freeBytes, totalBytes, totalFreeBytes uint64

	// GetDiskFreeSpaceExW(lpDirectoryName, &freeBytes, &totalBytes, &totalFreeBytes)
	ret, _, _ := proc.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(outDir))),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return nil // can't check — don't block
	}

	avail := int64(freeBytes)
	if avail < required {
		return fmt.Errorf("insufficient disk space at %s: %s available, ~%s needed",
			outDir, formatBytes(avail), formatBytes(required))
	}
	return nil
}
