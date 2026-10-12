package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alist-encrypt-go/shared/encryptcore"
)

func TestHandleEncryptFileRejectsChunkBeforeTask(t *testing.T) {
	for _, extra := range []string{`,"v3ChunkSize":-1`, `,"v3ChunkSize":33554433`, `,"v3ChunkSize":1.5`, `,"v3ChunkSize":"1048576"`, `,"v2":true,"v3ChunkSize":0`, `,"v2":true,"v3ChunkSize":1048576`} {
		t.Run(extra, func(t *testing.T) {
			src := t.TempDir()
			dst := filepath.Join(t.TempDir(), "not-created")
			before := len(encryptTaskStore.List())
			body := fmt.Sprintf(`{"password":"pw","operation":"enc","folderPath":%q,"outPath":%q%s}`, src, dst, extra)
			w := httptest.NewRecorder()
			HandleEncryptFile(w, httptest.NewRequest("POST", "/enc-api/encryptFile", bytes.NewBufferString(body)))
			var response struct {
				Code int
				Msg  string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Code == 0 {
				t.Fatalf("accepted %s: %s", extra, w.Body.String())
			}
			if len(encryptTaskStore.List()) != before {
				t.Fatal("invalid request created task")
			}
			if _, err := os.Stat(dst); !os.IsNotExist(err) {
				t.Fatalf("invalid request created directory: %v", err)
			}
		})
	}
}

func TestLocalV3ChunkBounds(t *testing.T) {
	for _, size := range []int64{0, 1, 1048576, 1048577, 33554432} {
		if err := validateLocalV3ChunkSize(size); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestRunEncryptTaskV3ChunkGeometryAndExactPlaintext(t *testing.T) {
	for _, chunk := range []int64{0, 1048576} {
		for _, size := range []int{0, 1048576 + 7} {
			t.Run(fmt.Sprintf("chunk%d/size%d", chunk, size), func(t *testing.T) {
				srcDir := t.TempDir()
				dstDir := t.TempDir()
				src := filepath.Join(srcDir, "plain")
				plain := bytes.Repeat([]byte{0x74}, size)
				if err := os.WriteFile(src, plain, 0600); err != nil {
					t.Fatal(err)
				}
				task := newEncryptTaskForTest(srcDir, dstDir, int64(size))
				task.V3 = true
				task.V3ChunkSize = chunk
				runEncryptTask(task, []string{src}, "chunk-test")
				snap := task.snapshot()
				if snap.Status != "done" || snap.V3ChunkSize != chunk {
					t.Fatalf("task: %+v", snap)
				}
				enc := filepath.Join(dstDir, "plain")
				data, err := os.ReadFile(enc)
				if err != nil {
					t.Fatal(err)
				}
				_, cs, _, ok := encryption.ParseV3StreamHeader(data)
				want := chunk
				if want == 0 {
					want = 16 * 1024 * 1024
				}
				records := (int64(size) + want - 1) / want
				if !ok || cs != uint64(want) || int64(len(data)) != encryption.V3HeaderSize+records*(want+16)+16 {
					t.Fatalf("geometry cs=%d bytes=%d", cs, len(data))
				}
				dec := filepath.Join(t.TempDir(), "dec")
				if err := processFile(enc, dec, "chunk-test", "chacha20", int64(len(data)), "dec", false); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(dec)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("plaintext got=%d want=%d", len(got), size)
				}
			})
		}
	}
}

func TestProcessFileRejectsChunkBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		v3    bool
		chunk int64
	}{{true, -1}, {true, 33554433}, {false, 1048576}} {
		dst := filepath.Join(t.TempDir(), "cipher")
		if err := processFile("missing", dst, "pw", "aesctr", 0, "enc", tc.v3, tc.chunk); err == nil {
			t.Fatal("accepted invalid options")
		}
		if _, err := os.Stat(dst); !os.IsNotExist(err) {
			t.Fatalf("created output: %v", err)
		}
	}
	// Rejected options must not affect the next legacy write.
	src := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(src, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "cipher")
	if err := processFile(src, dst, "pw", "chacha20", 6, "enc", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("CHC202")) {
		t.Fatal("legacy output changed")
	}
}
