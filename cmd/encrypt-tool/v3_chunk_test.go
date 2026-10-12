package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3ChunkValidation(t *testing.T) {
	for _, n := range []int64{0, 1, 1048576, 1048577, 33554432} {
		if err := (&flags{v3: true, v3ChunkSize: n}).validateV3Chunk("enc"); err != nil {
			t.Fatalf("%d: %v", n, err)
		}
	}
	for _, f := range []flags{{v3: true, v3ChunkSize: -1}, {v3: true, v3ChunkSize: 33554433}, {v3: true, v2: true, v3ChunkSet: true}, {v3: true, v2: true, v3ChunkSize: 1048576}} {
		if err := f.validateV3Chunk("enc"); err == nil {
			t.Fatalf("accepted %+v", f)
		}
	}
	if err := (&flags{v3: true, v3ChunkSet: true}).validateV3Chunk("dec"); err == nil {
		t.Fatal("accepted chunk option for decryption")
	}
}

func TestV3ChunkFlagParsing(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"encrypt-tool", "enc", "--v3-chunk-size", "1048576"}
	f := parseFlags("enc")
	if !f.v3ChunkSet || f.v3ChunkSize != 1048576 {
		t.Fatalf("flags: %+v", f)
	}
}

func TestV3ChunkRejectsBeforeOutput(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "output")
	if _, err := processOne("missing", dst, &flags{v3: true, v3ChunkSize: -1}, "enc"); err == nil {
		t.Fatal("accepted invalid chunk")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("created output: %v", err)
	}
}

func TestV3ChunkFileAndStdoutGeometry(t *testing.T) {
	for _, chunk := range []int64{0, 1048576} {
		for _, size := range []int{0, 1048576 + 7} {
			for _, stdout := range []bool{false, true} {
				t.Run(fmt.Sprintf("chunk%d/size%d/stdout%v", chunk, size, stdout), func(t *testing.T) {
					dir := t.TempDir()
					src := filepath.Join(dir, "plain")
					enc := filepath.Join(dir, "cipher")
					dec := filepath.Join(dir, "dec")
					plain := bytes.Repeat([]byte{0x39}, size)
					if err := os.WriteFile(src, plain, 0600); err != nil {
						t.Fatal(err)
					}
					f := &flags{v3: true, v3ChunkSize: chunk, password: "chunk-test", input: src, encType: "aesctr"}
					if stdout {
						out, err := os.Create(enc)
						if err != nil {
							t.Fatal(err)
						}
						old := os.Stdout
						os.Stdout = out
						func() { defer func() { os.Stdout = old }(); runEncryptStdout(f, int64(size)) }()
						if err := out.Close(); err != nil {
							t.Fatal(err)
						}
					} else if _, err := processOne(src, enc, f, "enc"); err != nil {
						t.Fatal(err)
					}
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
					// New-write options do not control old-container decoding.
					f.v3ChunkSize = 0
					f.v3ChunkSet = false
					if _, err := processOne(enc, dec, f, "dec"); err != nil {
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
}
