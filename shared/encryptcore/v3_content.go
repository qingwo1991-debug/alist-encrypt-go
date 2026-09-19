package encryption

import (
	"bytes"
	"fmt"
	"io"
)

// V3Magic is the exported identifier for the V3 stream header magic, letting
// small consumers (CLI tools, probes) sniff a container without importing
// internals.
const V3Magic = "V3GCM3"

// HasV3Magic reports whether prefix begins with the V3 container header magic.
func HasV3Magic(prefix []byte) bool {
	return len(prefix) >= v3MagicLen && bytes.Equal(prefix[:v3MagicLen], []byte(V3Magic))
}

// V3ContentEncryptor turns a plaintext reader into a V3 container stream. It
// is the equivalent of the V2-era NewLatestContentEncryptor for the V3 format:
// pick a chunk size (0 = default) and encrypt a reader whose output is a full
// V3 container (header + fixed-width chunk records + trailer).
type V3ContentEncryptor struct {
	chunkSize int64
}

// NewV3ContentEncryptor creates a container streamer. chunkSize <= 0 selects
// the default 16 MiB.
func NewV3ContentEncryptor(chunkSize int64) (*V3ContentEncryptor, error) {
	if chunkSize <= 0 || chunkSize > v3MaxChunkSize {
		chunkSize = v3DefaultChunkSize
	}
	return &V3ContentEncryptor{chunkSize: chunkSize}, nil
}

// EncryptReader streams r into a V3 container delivered on the returned
// reader.
func (e *V3ContentEncryptor) EncryptReader(password string, r io.Reader) (io.Reader, error) {
	if e == nil || r == nil {
		return nil, fmt.Errorf("v3: nil encryptor or source reader")
	}
	pr, pw := io.Pipe()
	go func() {
		vw, err := NewV3Writer(pw, password, e.chunkSize)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_, copyErr := io.Copy(vw, r)
		closeErr := vw.Close()
		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
			return
		}
		if closeErr != nil {
			_ = pw.CloseWithError(closeErr)
			return
		}
		_ = pw.Close()
	}()
	return pr, nil
}

// V3ReadableFile is what NewV3ReadSeekerDecoder needs: a source that supports
// both random access (ReadAt) and positioning (*os.File does).
type V3ReadableFile interface {
	io.Reader
	io.Seeker
	io.ReaderAt
}

// NewV3ReadSeekerDecoder opens a V3 container from a readable file handle and
// returns a reader over the decrypted plaintext.
func NewV3ReadSeekerDecoder(rs V3ReadableFile, size int64, password string) (io.Reader, error) {
	if rs == nil {
		return nil, fmt.Errorf("v3: nil reader")
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("v3: rewind container: %w", err)
	}
	container, err := OpenV3Container(rs, size, password)
	if err != nil {
		return nil, err
	}
	return container.Sequential(), nil
}
