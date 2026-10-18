package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	SnapshotFormat    = "alist-root-bolt-v1"
	SnapshotSchema    = "root-bolt-audit-v1"
	SnapshotSemantics = "committed transactions"
	snapshotChunk     = 64 * 1024
)

var ErrSnapshotBudget = errors.New("snapshot byte budget exceeded")

// SnapshotOptions bounds output, not wall-clock time spent inside a filesystem
// syscall or an arbitrary Writer.Write. A positive MaxBytes is required.
// Commit is an optional source revision (hex only), never arbitrary metadata.
type SnapshotOptions struct {
	MaxBytes int64
	Commit   string
}

// SnapshotManifest intentionally excludes record values and source paths. The
// database itself still contains sensitive original names, tokens and settings.
type SnapshotManifest struct {
	Format      string    `json:"format"`
	Schema      string    `json:"schema"`
	Component   string    `json:"component"`
	Commit      string    `json:"commit"`
	CreatedAt   time.Time `json:"created_at"`
	Bytes       int64     `json:"bytes"`
	SHA256      string    `json:"sha256"`
	TxID        uint64    `json:"tx_id"`
	Semantics   string    `json:"semantics"`
	Sensitivity string    `json:"sensitivity"`
}

func validSnapshotOptions(o SnapshotOptions) bool {
	if o.MaxBytes <= 0 {
		return false
	}
	if o.Commit == "" {
		return true
	}
	if len(o.Commit) != 40 && len(o.Commit) != 64 {
		return false
	}
	_, err := hex.DecodeString(o.Commit)
	return err == nil
}

type snapshotWriter struct {
	ctx  context.Context
	dst  io.Writer
	left int64
	err  error
}

func (w *snapshotWriter) Write(p []byte) (total int, err error) {
	defer func() {
		if err != nil {
			w.err = err
		}
	}()
	for len(p) > 0 {
		if err := w.ctx.Err(); err != nil {
			return total, err
		}
		if w.left == 0 {
			return total, ErrSnapshotBudget
		}
		size := len(p)
		if size > snapshotChunk {
			size = snapshotChunk
		}
		if int64(size) > w.left {
			size = int(w.left)
		}
		n, err := w.dst.Write(p[:size])
		if n < 0 || n > size {
			return total, errors.New("invalid snapshot writer count")
		}
		total += n
		w.left -= int64(n)
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n != size {
			return total, io.ErrShortWrite
		}
		if err := w.ctx.Err(); err != nil {
			return total, err
		}
	}
	return total, nil
}

// Snapshot writes the entire database using exactly one read transaction. TxID
// is tx.ID(), not the process-local attempted-write counter. Caller owns dst;
// Snapshot never closes it. Cancellation is cooperative between bounded writes;
// arbitrary blocking writers cannot be interrupted and no worker is abandoned.
func (s *Store) Snapshot(ctx context.Context, dst io.Writer, o SnapshotOptions) (SnapshotManifest, error) {
	var m SnapshotManifest
	if ctx == nil || dst == nil || !validSnapshotOptions(o) {
		return m, errors.New("invalid snapshot arguments")
	}
	if err := ctx.Err(); err != nil {
		return m, err
	}
	if err := s.filenameReady(); err != nil {
		return m, err
	}
	hash := sha256.New()
	w := &snapshotWriter{ctx: ctx, dst: io.MultiWriter(dst, hash), left: o.MaxBytes}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tx.Size() > o.MaxBytes {
			return ErrSnapshotBudget
		}
		m = SnapshotManifest{Format: SnapshotFormat, Schema: SnapshotSchema, Component: "root-bolt", Commit: strings.ToLower(o.Commit), CreatedAt: time.Now().UTC(), TxID: uint64(tx.ID()), Semantics: SnapshotSemantics, Sensitivity: "sensitive-unencrypted"}
		n, err := tx.WriteTo(w)
		m.Bytes = n
		// bbolt versions may add non-wrapping WriteTo context. Preserve the
		// underlying cancellation/budget/short-write error for errors.Is.
		return errors.Join(err, w.err)
	})
	if err != nil {
		return SnapshotManifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return SnapshotManifest{}, err
	}
	m.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return m, nil
}

// CreateSnapshot publishes a verified tar bundle in an existing, trusted local
// directory. name is a basename, never a path. Files are 0600; staging is 0700.
// Publication uses a same-filesystem hard link, NOT an overwriting rename.
// An error after publication (e.g. directory fsync) may leave a valid bundle;
// neither it nor any previous backup is removed. No retention deletion occurs.
func (s *Store) CreateSnapshot(ctx context.Context, directory, name string, o SnapshotOptions) (m SnapshotManifest, err error) {
	if ctx == nil || !validSnapshotOptions(o) || name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return m, errors.New("invalid snapshot destination/options")
	}
	if err = ctx.Err(); err != nil {
		return m, err
	}
	stage, err := os.MkdirTemp(directory, ".bolt-snapshot-")
	if err != nil {
		return m, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	dbPath := filepath.Join(stage, "database.bolt")
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return m, err
	}
	m, err = s.Snapshot(ctx, f, o)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return m, err
	}
	if err = ValidateSnapshot(ctx, dbPath, m); err != nil {
		return m, err
	}
	bundlePath := filepath.Join(stage, "bundle.tar")
	bundle, err := os.OpenFile(bundlePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return m, err
	}
	err = writeSnapshotBundle(ctx, bundle, dbPath, m, o.MaxBytes)
	if err == nil {
		err = bundle.Sync()
	}
	err = errors.Join(err, bundle.Close())
	if err != nil {
		return m, err
	}
	// Validate the actual packaged bytes before publication, not just its input.
	if err = ValidateSnapshotBundle(ctx, bundlePath, o.MaxBytes); err != nil {
		return m, err
	}
	if err = ctx.Err(); err != nil {
		return m, err
	}
	if err = os.Link(bundlePath, filepath.Join(directory, name)); err != nil {
		return m, err
	}
	dir, openErr := os.Open(directory)
	if openErr != nil {
		return m, openErr
	}
	err = errors.Join(dir.Sync(), dir.Close())
	return m, err
}

func writeSnapshotBundle(ctx context.Context, dst io.Writer, dbPath string, m SnapshotManifest, max int64) (err error) {
	tw := tar.NewWriter(dst)
	defer func() { err = errors.Join(err, tw.Close()) }()
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	if _, err = tw.Write(raw); err != nil {
		return err
	}
	if err = tw.WriteHeader(&tar.Header{Name: "database.bolt", Mode: 0600, Size: m.Bytes, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	f, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	_, err = io.Copy(&snapshotWriter{ctx: ctx, dst: tw, left: max}, f)
	return err
}

// validateStandaloneTar inspects physical headers before archive/tar can hide
// PAX/GNU extension records or stop at its first end marker. Only two owned
// USTAR regular members followed by at least two zero blocks are accepted.
// Additional all-zero padding is harmless; concatenated archives are not.
func validateStandaloneTar(ctx context.Context, f *os.File, size int64) error {
	if size < 1024 || size%512 != 0 {
		return errors.New("invalid standalone tar size")
	}
	var block [512]byte
	var offset int64
	members := 0
	for offset < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := f.ReadAt(block[:], offset); err != nil {
			return err
		}
		if bytes.Equal(block[:], make([]byte, 512)) {
			if members != 2 || size-offset < 1024 {
				return errors.New("incomplete tar terminator")
			}
			for offset < size {
				if err := ctx.Err(); err != nil {
					return err
				}
				if _, err := f.ReadAt(block[:], offset); err != nil {
					return err
				}
				for _, b := range block {
					if b != 0 {
						return errors.New("nonzero trailing tar data")
					}
				}
				offset += 512
			}
			return nil
		}
		if members >= 2 || block[156] != tar.TypeReg || string(block[257:263]) != "ustar\x00" || string(block[263:265]) != "00" {
			return errors.New("unsupported physical tar header")
		}
		name := string(bytes.TrimRight(block[:100], "\x00"))
		if (members == 0 && name != "manifest.json") || (members == 1 && name != "database.bolt") {
			return errors.New("unexpected tar member order")
		}
		// Reject prefix/link/user/group and extension metadata, even if tar's
		// logical Header would hide it. Remaining header padding is zero.
		for _, region := range [][]byte{block[157:257], block[265:329], block[345:512]} {
			for _, b := range region {
				if b != 0 {
					return errors.New("unexpected tar header metadata")
				}
			}
		}
		payload, err := strconv.ParseInt(strings.Trim(string(block[124:136]), " \x00"), 8, 64)
		if err != nil || payload < 0 || payload > size-offset-512 {
			return errors.New("invalid tar member size")
		}
		blocks := payload / 512
		if payload%512 != 0 {
			blocks++
		}
		offset += 512 + blocks*512
		members++
	}
	return errors.New("missing tar terminator")
}

// ValidateSnapshotBundle verifies only; it never opens a production database for
// writing. Controlled temporary extraction is removed before return.
func ValidateSnapshotBundle(ctx context.Context, bundlePath string, maxBytes int64) (err error) {
	if ctx == nil || maxBytes <= 0 {
		return errors.New("invalid bundle validation arguments")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(bundlePath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	// Bound tar parsing as well as its database member; reject oversized
	// extension/trailing data before archive/tar can consume it.
	if !info.Mode().IsRegular() || info.Size() > maxBytes && info.Size()-maxBytes > 1<<20 {
		return ErrSnapshotBudget
	}
	if err = validateStandaloneTar(ctx, f, info.Size()); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(bundlePath), ".bolt-validate-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	tr := tar.NewReader(f)
	var m SnapshotManifest
	seen := map[string]bool{}
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if seen[h.Name] || h.Typeflag != tar.TypeReg || h.Mode != 0600 || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 || h.Linkname != "" || h.Uname != "" || h.Gname != "" || h.Uid != 0 || h.Gid != 0 {
			return errors.New("invalid bundle member")
		}
		seen[h.Name] = true
		switch h.Name {
		case "manifest.json":
			if h.Size <= 0 || h.Size > 8192 {
				return errors.New("invalid manifest size")
			}
			raw, e := io.ReadAll(tr)
			if e != nil {
				return e
			}
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if e = dec.Decode(&m); e != nil {
				return e
			}
			var extra any
			if e = dec.Decode(&extra); e != io.EOF {
				return errors.New("trailing manifest data")
			}
		case "database.bolt":
			if h.Size <= 0 || h.Size > maxBytes {
				return ErrSnapshotBudget
			}
			out, e := os.OpenFile(filepath.Join(stage, "database.bolt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			_, e = io.Copy(&snapshotWriter{ctx: ctx, dst: out, left: maxBytes}, tr)
			e = errors.Join(e, out.Close())
			if e != nil {
				return e
			}
		default:
			return errors.New("unknown bundle member")
		}
	}
	if !seen["manifest.json"] || !seen["database.bolt"] {
		return errors.New("incomplete bundle")
	}
	if err = ValidateSnapshot(ctx, filepath.Join(stage, "database.bolt"), m); err != nil {
		return fmt.Errorf("bundle validation: %w", err)
	}
	return nil
}
