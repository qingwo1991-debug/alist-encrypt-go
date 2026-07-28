package handler

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
)

func TestRunEncryptTaskCreatesNestedOutputAndPublishesFile(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	input := bytes.Repeat([]byte("nested-video-data"), 128)
	srcFile := filepath.Join(srcDir, "season", "episode.dat")
	if err := os.MkdirAll(filepath.Dir(srcFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcFile, input, 0o600); err != nil {
		t.Fatal(err)
	}

	task := newEncryptTaskForTest(srcDir, dstDir, int64(len(input)))
	runEncryptTask(task, []string{srcFile}, "test-password")

	snapshot := task.snapshot()
	if snapshot.Status != "done" {
		t.Fatalf("status = %q, error = %q; want done", snapshot.Status, snapshot.Error)
	}
	if snapshot.DoneFiles != 1 || snapshot.DoneBytes != int64(len(input)) {
		t.Fatalf("progress = %d files/%d bytes; want 1/%d", snapshot.DoneFiles, snapshot.DoneBytes, len(input))
	}

	encryptedFile := filepath.Join(dstDir, "season", "episode.dat")
	encryptedInfo, err := os.Stat(encryptedFile)
	if err != nil {
		t.Fatalf("nested output was not published: %v", err)
	}
	decryptedFile := filepath.Join(t.TempDir(), "episode.dat")
	if err := processFile(encryptedFile, decryptedFile, "test-password", "aesctr", encryptedInfo.Size(), "dec"); err != nil {
		t.Fatalf("decrypt generated output: %v", err)
	}
	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, input) {
		t.Fatal("published nested output does not decrypt to the original content")
	}
	assertNoEncryptTempDirs(t, dstDir, task.ID)
}

func TestRunEncryptTaskRenameFailureSetsErrorAndDoesNotAdvance(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	input := []byte("rename failure must not be reported as success")
	srcFile := filepath.Join(srcDir, "nested", "movie.dat")
	if err := os.MkdirAll(filepath.Dir(srcFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcFile, input, 0o600); err != nil {
		t.Fatal(err)
	}

	// Publishing a regular file over an existing directory must make Rename fail.
	outFile := filepath.Join(dstDir, "nested", "movie.dat")
	if err := os.MkdirAll(outFile, 0o755); err != nil {
		t.Fatal(err)
	}

	task := newEncryptTaskForTest(srcDir, dstDir, int64(len(input)))
	runEncryptTask(task, []string{srcFile}, "test-password")

	snapshot := task.snapshot()
	if snapshot.Status != "error" {
		t.Fatalf("status = %q; want error", snapshot.Status)
	}
	if !strings.Contains(snapshot.Error, "publish ") {
		t.Fatalf("error = %q; want publish failure", snapshot.Error)
	}
	if snapshot.DoneFiles != 0 || snapshot.DoneBytes != 0 {
		t.Fatalf("failed publish advanced progress to %d files/%d bytes", snapshot.DoneFiles, snapshot.DoneBytes)
	}
	if info, err := os.Stat(outFile); err != nil || !info.IsDir() {
		t.Fatalf("failed publish replaced destination directory: info=%v err=%v", info, err)
	}
	assertNoEncryptTempDirs(t, dstDir, task.ID)
}

func TestRunEncryptTaskMissingEnumeratedFileSetsError(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	missing := filepath.Join(srcDir, "vanished.dat")
	task := newEncryptTaskForTest(srcDir, dstDir, 42)

	runEncryptTask(task, []string{missing}, "test-password")

	snapshot := task.snapshot()
	if snapshot.Status != "error" || !strings.Contains(snapshot.Error, "stat ") {
		t.Fatalf("status/error = %q/%q; want stat error", snapshot.Status, snapshot.Error)
	}
	if snapshot.DoneFiles != 0 || snapshot.DoneBytes != 0 {
		t.Fatalf("missing file advanced progress to %d files/%d bytes", snapshot.DoneFiles, snapshot.DoneBytes)
	}
}

func TestRunDecryptTaskRejectsEscapingDecodedName(t *testing.T) {
	rootDir := t.TempDir()
	srcDir := filepath.Join(rootDir, "src")
	dstDir := filepath.Join(rootDir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatal(err)
	}

	password := "test-password"
	plain := filepath.Join(rootDir, "plain.dat")
	content := []byte("decoded filenames must stay inside the output directory")
	if err := os.WriteFile(plain, content, 0o600); err != nil {
		t.Fatal(err)
	}

	converter := encryption.NewFileNameConverter(password, "aesctr", "")
	craftedName := converter.EncryptFileName("../escape") + ".dat"
	encrypted := filepath.Join(srcDir, craftedName)
	if err := processFile(plain, encrypted, password, "aesctr", int64(len(content)), "enc"); err != nil {
		t.Fatalf("create encrypted fixture: %v", err)
	}
	encryptedInfo, err := os.Stat(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	task := newEncryptTaskForTest(srcDir, dstDir, encryptedInfo.Size())
	task.Operation = "dec"
	task.EncName = true
	runEncryptTask(task, []string{encrypted}, password)

	snapshot := task.snapshot()
	if snapshot.Status != "error" || !strings.Contains(snapshot.Error, "unsafe decoded filename") {
		t.Fatalf("status/error = %q/%q; want unsafe filename error", snapshot.Status, snapshot.Error)
	}
	if _, err := os.Stat(filepath.Join(rootDir, "escape.dat")); !os.IsNotExist(err) {
		t.Fatalf("decoded output escaped destination directory: err=%v", err)
	}
}

func newEncryptTaskForTest(srcDir, dstDir string, totalBytes int64) *EncryptTask {
	now := time.Now()
	return &EncryptTask{
		ID:         "test-task",
		Operation:  "enc",
		EncType:    "aesctr",
		SrcPath:    srcDir,
		DstPath:    dstDir,
		TotalFiles: 1,
		TotalBytes: totalBytes,
		Status:     "running",
		CreatedAt:  now,
		UpdatedAt:  now,
		cancel:     make(chan struct{}),
	}
}

func assertNoEncryptTempDirs(t *testing.T, dstDir, taskID string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dstDir, ".encrypt-"+taskID+"-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary task directories were not removed: %v", matches)
	}
}
