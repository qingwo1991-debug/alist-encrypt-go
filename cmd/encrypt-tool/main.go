// Package main provides a standalone CLI tool for encrypting/decrypting files.
//
//	encrypt-tool enc --password-file <path> -i <input> [-o output] [-t aesctr] [-n] [-s .bin] [-w 4] [-v]
//	encrypt-tool dec --password-file <path> -i <input> [-o output] [-w 4] [-v]
//
// Encryption produces V2-format files fully compatible with the alist-encrypt-go proxy:
// content uses NewLatestContentEncryptor (32-byte V2 header), filenames use the same
// EncodeName(full_filename) + suffix format as the proxy's ConvertRealNameWithSuffix.
//
// Decryption is fully automatic: V1/V2 auto-detected from header, encType auto-detected
// from V2 magic bytes (AECTR2/CHC202/RC4MD2), suffix auto-stripped, filename auto-decrypted
// via CRC6 verification. Only the password is required.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
)

const version = "1.2.0"

// verifySampleSize is how many bytes we read back after encryption to verify correctness.
const verifySampleSize = 4096

// progressThreshold is the file size above which progress is auto-shown
// even without -v.  Below this, progress is only shown in verbose mode.
const progressThreshold = 100 * 1024 * 1024 // 100 MB

// progressInterval controls how often progress is printed to stderr.
const progressInterval = 3 * time.Second

// logHandle is the optional error log file (nil when --log not used).
var logHandle *os.File

// knownSuffixes are always safe to strip during decryption.
var knownSuffixes = []string{".bin", ".enc", ".dat"}

// allEncTypes is tried in order when auto-detecting from V1 files.
var allEncTypes = []string{"aesctr", "chacha20", "rc4md5"}

// knownFileSignatures lists common file magic bytes for content-based detection.
// Used when V2 header magic is absent and filename CRC6 fails — we decrypt a
// small sample with each algorithm and check if the result matches a known file
// signature.  At least 3 bytes per signature keeps false positives negligible.
var knownFileSignatures = []struct {
	offset int
	magic  []byte
}{
	{4, []byte("ftyp")},                             // MP4/MOV/HEIF/3GP
	{0, []byte{0x1A, 0x45, 0xDF, 0xA3}},             // MKV/WebM (EBML)
	{0, []byte("RIFF")},                             // AVI/WAV
	{0, []byte{0x50, 0x4B, 0x03, 0x04}},             // ZIP/DOCX/XLSX/APK
	{0, []byte("Rar!\x1a\x07")},                     // RAR
	{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}}, // 7z
	{0, []byte{0x1F, 0x8B, 0x08}},                   // GZIP
	{0, []byte("%PDF")},                             // PDF
	{0, []byte{0x89, 0x50, 0x4E, 0x47}},             // PNG
	{0, []byte{0xFF, 0xD8, 0xFF}},                   // JPEG
	{0, []byte("GIF87a")},                           // GIF
	{0, []byte("GIF89a")},                           // GIF
	{0, []byte("ID3")},                              // MP3 (ID3 tag)
	{0, []byte("fLaC")},                             // FLAC
	{0, []byte("OggS")},                             // OGG
	{0, []byte{0xD0, 0xCF, 0x11, 0xE0}},             // MS Office legacy (doc/xls/ppt)
	{0, []byte{0x7F, 0x45, 0x4C, 0x46}},             // ELF binary
	{0, []byte("BM")},                               // BMP (2 bytes — weaker)
}

// hasKnownFileSignature checks whether the given decrypted bytes start with
// a recognized file magic signature.
func hasKnownFileSignature(data []byte) bool {
	for _, sig := range knownFileSignatures {
		end := sig.offset + len(sig.magic)
		if end <= len(data) && bytes.Equal(data[sig.offset:end], sig.magic) {
			return true
		}
	}
	return false
}

// flags holds all parsed command-line options.
type flags struct {
	password     string
	passwordFile string // read password from file instead of exposing it in process arguments
	input        string
	output       string
	encType      string // "auto" for dec; "aesctr"/"chacha20"/"rc4md5" for enc
	encName      bool   // enc only: encrypt filenames
	suffix       string // enc only: suffix to append
	workers      int    // parallel workers for batch mode
	verbose      bool
	logFile      string // --log: path to error log file
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "enc", "dec":
		run(cmd)
	case "-h", "--help", "help":
		printUsage()
	case "-v", "--version":
		fmt.Printf("encrypt-tool %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func run(command string) {
	f := parseFlags(command)

	if err := loadPassword(f); err != nil {
		fatal("%s", err)
	}

	// Open error log file if requested.
	if f.logFile != "" {
		lf, err := os.OpenFile(f.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fatal("cannot open log file %s: %v", f.logFile, err)
		}
		logHandle = lf
		defer logHandle.Close()
		logLine("=== encrypt-tool %s started: %s %s ===", version, command, f.input)
	}

	if command == "enc" && f.encType == "auto" {
		f.encType = "aesctr"
	}
	// Auto-tune workers: 0 (unset) → NumCPU
	if f.workers == 0 {
		f.workers = runtime.NumCPU()
	}
	if f.workers < 1 {
		f.workers = 1
	}

	// Warn if worker count exceeds CPU cores (memory is tiny per worker,
	// but CPU-bound crypto means extra workers just add scheduler overhead).
	if cpu := runtime.NumCPU(); f.workers > cpu {
		warnf("Note: -w %d > %d CPU cores; extra workers may reduce throughput\n", f.workers, cpu)
	}

	if f.input == "" {
		fatal("-i/--input is required")
	}

	info, err := os.Stat(f.input)
	if err != nil {
		fatal("cannot access input path: %v", err)
	}

	if info.IsDir() {
		runBatch(command, f)
	} else {
		runSingle(command, f, info.Size())
	}
}

// ---------------------------------------------------------------------------
// Single file mode
// ---------------------------------------------------------------------------

func runSingle(command string, f *flags, fileSize int64) {
	outFile, skip := resolveOutputPath(f.input, f, command, "")
	if skip {
		fmt.Println("Skipping: source and output are the same file")
		return
	}

	// Disk space pre-check (warn only)
	outDir := filepath.Dir(outFile)
	if err := checkDiskSpace(outDir, fileSize); err != nil {
		warnf("Warning: %v\n", err)
	}

	logf(f.verbose, "%s file (%s)...\n", opName(command), formatBytes(fileSize))
	n, err := processOne(f.input, outFile, f, command)
	if err != nil {
		fatal("%s", err)
	}

	if command == "enc" {
		if verifyErr := verifyEncryption(f.input, outFile, f); verifyErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: verification failed for %s: %v\n", outFile, verifyErr)
		} else {
			logf(f.verbose, "Verification OK (first %d bytes match)\n", verifySampleSize)
		}
	}

	fmt.Printf("Done: 1 file, %s %s → %s\n", formatBytes(n), opName(command)+"ed", outFile)
}

// ---------------------------------------------------------------------------
// Batch (directory) mode with worker pool
// ---------------------------------------------------------------------------

type fileJob struct {
	srcPath  string
	outFile  string
	fileSize int64
	index    int
}

func runBatch(command string, f *flags) {
	var jobs []fileJob
	var totalBytes int64

	err := filepath.WalkDir(f.input, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, e := d.Info()
		if e != nil || fi.Size() == 0 {
			return nil
		}
		outFile, skip := resolveOutputPath(path, f, command, f.input)
		if skip {
			return nil
		}
		jobs = append(jobs, fileJob{srcPath: path, outFile: outFile, fileSize: fi.Size(), index: len(jobs)})
		totalBytes += fi.Size()
		return nil
	})
	if err != nil {
		fatal("walking directory: %v", err)
	}
	if len(jobs) == 0 {
		fatal("no non-empty files found in: %s", f.input)
	}

	// Disk space pre-check (warn only)
	if f.output != "" {
		if err := checkDiskSpace(f.output, totalBytes); err != nil {
			warnf("Warning: %v\n", err)
		}
	}

	total := len(jobs)
	workers := f.workers
	if workers > total {
		workers = total
	}

	logf(f.verbose, "Found %d files (%s), %s with %d workers...\n",
		total, formatBytes(totalBytes), opName(command), workers)

	var done atomic.Int64
	var doneBytes atomic.Int64
	var errs atomic.Int64
	errMsgs := make([]string, 0)
	var mu sync.Mutex

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j fileJob) {
			defer wg.Done()
			defer func() { <-sem }()

			n, err := processOne(j.srcPath, j.outFile, f, command)

			d := done.Add(1)
			doneBytes.Add(n)

			if err != nil {
				errs.Add(1)
				errMsg := fmt.Sprintf("  %s: %v", j.srcPath, err)
				mu.Lock()
				errMsgs = append(errMsgs, errMsg)
				mu.Unlock()
				logLine("ERROR: %s: %v", j.srcPath, err)
			} else if command == "enc" {
				if vErr := verifyEncryption(j.srcPath, j.outFile, f); vErr != nil {
					mu.Lock()
					errMsgs = append(errMsgs, fmt.Sprintf("  %s: verification failed: %v", j.srcPath, vErr))
					mu.Unlock()
					logLine("VERIFY FAIL: %s: %v", j.srcPath, vErr)
				}
			}

			if f.verbose {
				pct := float64(d) / float64(total) * 100
				fmt.Fprintf(os.Stderr, "  [%d/%d] %.0f%%  %s\n", d, total, pct, filepath.Base(j.srcPath))
			}
		}(jobs[i])
	}
	wg.Wait()

	fmt.Printf("\nDone: %d/%d files, %s %s", done.Load(), total, formatBytes(doneBytes.Load()), opName(command)+"ed")
	logLine("BATCH DONE: %d/%d files, %s %s, errors=%d",
		done.Load(), total, formatBytes(doneBytes.Load()), opName(command), errs.Load())
	if e := errs.Load(); e > 0 {
		fmt.Fprintf(os.Stderr, "\nErrors (%d):\n", e)
		for _, m := range errMsgs {
			fmt.Fprintln(os.Stderr, m)
		}
		os.Exit(1)
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Output path resolution
// ---------------------------------------------------------------------------

// resolveOutputPath determines the destination file path.
//
// Encryption filename format (with -n, matching proxy's ConvertRealNameWithSuffix):
//
//	EncodeName(full_filename_including_ext) + suffix
//	e.g. oceans.mp4 → EncodeName("oceans.mp4").bin
//
// Without -n: original_name + suffix
//
//	e.g. oceans.mp4 → oceans.mp4.bin
//
// Decryption: auto-detect everything — strip suffix, try CRC6 decode on filename.
func resolveOutputPath(srcPath string, f *flags, command, baseDir string) (string, bool) {
	var relPath string
	if baseDir != "" {
		rel, _ := filepath.Rel(baseDir, srcPath)
		relPath = rel
	} else {
		relPath = filepath.Base(srcPath)
	}

	dir := filepath.Dir(relPath)
	fileName := filepath.Base(relPath)
	var outName string

	if command == "enc" {
		outName = encryptOutputName(fileName, f)
	} else {
		outName = autoDecryptOutputName(fileName, srcPath, f)
	}

	outRel := filepath.Join(dir, outName)

	if f.output == "" {
		var outPath string
		if baseDir != "" {
			outPath = filepath.Join(baseDir, outRel)
		} else {
			outPath = filepath.Join(filepath.Dir(srcPath), outName)
		}
		// Avoid truncating the source when the name didn't change.
		srcAbs, _ := filepath.Abs(srcPath)
		outAbs, _ := filepath.Abs(outPath)
		if srcAbs == outAbs {
			return "", true
		}
		return outPath, false
	}

	// Output path specified.
	// If it's an existing directory → place file inside it.
	// If it doesn't exist → treat as explicit output file path (single-file mode)
	//   or as a directory to create (batch mode, baseDir != "").
	outInfo, err := os.Stat(f.output)
	if err == nil {
		// Output exists: if it's a directory, place file inside; otherwise overwrite.
		if outInfo.IsDir() || baseDir != "" {
			var outPath string
			if baseDir == "" {
				outPath = filepath.Join(f.output, outName)
			} else {
				outPath = filepath.Join(f.output, outRel)
			}
			srcAbs, _ := filepath.Abs(srcPath)
			outAbs, _ := filepath.Abs(outPath)
			if srcAbs == outAbs {
				return "", true
			}
			return outPath, false
		}
		// Existing file path → overwrite directly.
		return f.output, false
	}

	// Output path doesn't exist yet.
	if baseDir != "" {
		// Batch mode: create as directory, preserve relative structure.
		outPath := filepath.Join(f.output, outRel)
		srcAbs, _ := filepath.Abs(srcPath)
		outAbs, _ := filepath.Abs(outPath)
		if srcAbs == outAbs {
			return "", true
		}
		return outPath, false
	}
	// Single-file mode: treat as explicit file path.
	return f.output, false
}

// encryptOutputName produces the encrypted filename.
//
// With filename encryption (-n):
//
//	EncodeName(password, encType, fullFileName) + suffix
//	This matches the proxy's ConvertRealNameWithSuffix exactly.
//
// Without filename encryption:
//
//	originalFileName + suffix
func encryptOutputName(fileName string, f *flags) string {
	suffix := f.suffix
	if suffix != "" && !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}

	if f.encName {
		// Encrypt the FULL filename (including extension), then append suffix.
		// This is the same as the proxy's ConvertRealNameWithSuffix.
		encName := encryption.EncodeName(f.password, f.encType, fileName)
		return encName + suffix
	}

	// No filename encryption — just append suffix to original name.
	if suffix != "" && strings.HasSuffix(fileName, suffix) {
		return fileName
	}
	return fileName + suffix
}

// autoDecryptOutputName determines the output filename for a decrypted file.
// It auto-detects the encryption type, strips the suffix, and tries to
// decrypt the filename via CRC6 verification.
func autoDecryptOutputName(fileName, srcPath string, f *flags) string {
	encType := f.encType
	if encType == "auto" || encType == "" {
		encType = string(detectEncType(srcPath, f.password))
	}

	// Step 1: Strip known encrypted suffixes (.bin, .enc, .dat) BEFORE
	// trying to decode.  This prevents tryDecodeName's V1 fallback from
	// treating the suffix as a file extension to preserve.
	stripped := fileName
	suffixWasStripped := false
	for _, s := range knownSuffixes {
		if strings.HasSuffix(stripped, s) {
			stripped = strings.TrimSuffix(stripped, s)
			suffixWasStripped = true
			break
		}
	}

	// Step 2: Try decoding (handles both V1 and V2 filename formats)
	if decoded := tryDecodeName(stripped, f.password, encType); decoded != "" {
		return decoded
	}

	// Step 3: If we stripped a suffix but decoding failed, the name was
	// not encrypted — return without the suffix.
	if suffixWasStripped {
		return stripped
	}

	// Step 4: Try stripping last extension as a potential custom suffix.
	// Only accept if decode succeeds — otherwise it's a real file extension.
	lastExt := filepath.Ext(fileName)
	if lastExt != "" {
		customStripped := strings.TrimSuffix(fileName, lastExt)
		if decoded := tryDecodeName(customStripped, f.password, encType); decoded != "" {
			return decoded
		}
	}

	// Step 5: No decode worked — filename wasn't encrypted
	return fileName
}

// tryDecodeName attempts to decrypt a filename using CRC6 verification.
//
// Two filename formats are supported:
//
//	V2 (with or without suffix): EncodeName(fullName) → "XyZ…G"
//	  The entire filename was encrypted, so DecodeName returns the complete
//	  original name (including extension). No ext appending needed.
//
//	V1 (no suffix): EncodeName(baseName) → "XyZ…O" + ".mp4"
//	  Only the baseName was encrypted; the extension is plaintext and must
//	  be appended back after decoding.
//
// The heuristic for distinguishing: if DecodeName succeeds on the full name
// (Try 1), the result is complete.  If it only succeeds on the baseName
// (Try 2), check whether the decoded result already has an extension —
// if yes, the stripped ext was a custom suffix (don't append); if no,
// it was a V1-preserved extension (append it).
func tryDecodeName(name, password, encType string) string {
	// Try 1: entire name is encrypted (V2 format, suffix already stripped)
	if decoded := encryption.DecodeName(password, encType, name); decoded != "" {
		return decoded
	}

	// Try 2: baseName is encrypted, extension preserved (V1 format)
	ext := filepath.Ext(name)
	if ext == "" {
		return ""
	}
	baseName := strings.TrimSuffix(name, ext)
	if baseName == "" {
		return ""
	}
	decoded := encryption.DecodeName(password, encType, baseName)
	if decoded == "" {
		return ""
	}

	// Only append the stripped extension if the decoded result doesn't
	// already have one.  V1 baseName decode → "video" (no ext) → append.
	// V2 with unknown custom suffix → "video.mp4" (has ext) → don't append.
	if filepath.Ext(decoded) == "" {
		return decoded + ext
	}
	return decoded
}

// ---------------------------------------------------------------------------
// Encryption type auto-detection
// ---------------------------------------------------------------------------

// detectEncType returns the detected encryption type. For details about
// which detection method was used, call detectEncTypeVerbose.
func detectEncType(filePath, password string) encryption.EncType {
	t, _ := detectEncTypeVerbose(filePath, password)
	return t
}

// detectEncTypeVerbose returns the encryption type and a human-readable
// detection method string.  Detection cascade:
//
//  1. V2 magic bytes (AECTR2/CHC202/RC4MD2) — 100% reliable
//  2. Filename CRC6 — ~98.4% reliable per algorithm (1/64 false positive)
//  3. Content file signature — decrypt first 256 bytes, check magic bytes
//  4. Default to aesctr — uncertain, caller should warn
func detectEncTypeVerbose(filePath, password string) (encryption.EncType, string) {
	header := make([]byte, 6)
	f, err := os.Open(filePath)
	if err != nil {
		return encryption.EncTypeAESCTR, "default"
	}
	n, _ := io.ReadFull(f, header)
	f.Close()

	// Layer 1: V2 magic bytes
	if n >= 6 {
		switch string(header[:6]) {
		case "AECTR2":
			return encryption.EncTypeAESCTR, "v2-magic"
		case "CHC202":
			return encryption.EncTypeChaCha20, "v2-magic"
		case "RC4MD2":
			return encryption.EncTypeRC4MD5, "v2-magic"
		}
	}

	// Layer 2: V1 filename CRC6
	fileName := filepath.Base(filePath)
	workName := fileName
	for _, s := range knownSuffixes {
		if strings.HasSuffix(workName, s) {
			workName = strings.TrimSuffix(workName, s)
			break
		}
	}

	// Try both the full workName (no extension — V2 with suffix stripped)
	// and the baseName (V1 style: encrypted baseName + plaintext extension).
	ext := filepath.Ext(workName)
	baseName := strings.TrimSuffix(workName, ext)

	for _, candidate := range []string{workName, baseName} {
		if candidate == "" {
			continue
		}
		for _, t := range allEncTypes {
			if encryption.DecodeName(password, t, candidate) != "" {
				return encryption.EncType(t), "filename-crc6"
			}
		}
	}

	// Layer 3: Content-based detection — decrypt a sample and check signatures
	if t, ok := detectEncTypeByContent(filePath, password); ok {
		return t, "content-signature"
	}

	// Layer 4: give up — default to aesctr
	return encryption.EncTypeAESCTR, "default"
}

// detectEncTypeByContent reads the first 256 bytes, decrypts them with each
// algorithm, and checks whether the decrypted data starts with a known file
// signature (MP4 ftyp, ZIP PK, PDF %PDF, etc.).  This catches V1 files whose
// filenames are not encrypted or whose CRC6 didn't match.
func detectEncTypeByContent(filePath, password string) (encryption.EncType, bool) {
	info, err := os.Stat(filePath)
	if err != nil {
		return encryption.EncTypeAESCTR, false
	}
	fileSize := info.Size()

	f, err := os.Open(filePath)
	if err != nil {
		return encryption.EncTypeAESCTR, false
	}
	defer f.Close()

	sample := make([]byte, 256)
	n, err := io.ReadFull(f, sample)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return encryption.EncTypeAESCTR, false
	}
	sample = sample[:n]
	if n < 4 {
		return encryption.EncTypeAESCTR, false
	}

	for _, encType := range allEncTypes {
		reader, _, err := encryption.AutoDecryptReader(
			password, encryption.EncType(encType),
			bytes.NewReader(sample), fileSize,
		)
		if err != nil {
			continue
		}
		decrypted := make([]byte, 64)
		decN, _ := io.ReadFull(reader, decrypted)
		decrypted = decrypted[:decN]

		if decN > 0 && hasKnownFileSignature(decrypted) {
			return encryption.EncType(encType), true
		}
	}

	return encryption.EncTypeAESCTR, false
}

// ---------------------------------------------------------------------------
// Progress reporting & disk space
// ---------------------------------------------------------------------------

// shouldShowProgress returns true if progress should be auto-displayed.
// Large files (> progressThreshold) always get progress; small files only in verbose.
func shouldShowProgress(fileSize int64, verbose bool) bool {
	return verbose || fileSize > progressThreshold
}

// copyWithProgress streams from src to dst, reporting throughput and ETA to
// stderr every progressInterval.  Uses the provided buffer for I/O.
func copyWithProgress(dst io.Writer, src io.Reader, buf []byte, totalSize int64, name string, showProgress bool) (int64, error) {
	var written int64
	start := time.Now()
	lastReport := start

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nr < nw {
				return written, fmt.Errorf("invalid write: %d/%d", nw, nr)
			}
			if ew != nil {
				return written + int64(nw), ew
			}
			written += int64(nw)
			if nr != nw {
				return written, fmt.Errorf("short write: %d != %d", nw, nr)
			}

			if showProgress {
				now := time.Now()
				if now.Sub(lastReport) >= progressInterval {
					lastReport = now
					printProgress(name, written, totalSize, start)
				}
			}
		}
		if er != nil {
			if er == io.EOF {
				if showProgress && written > 0 {
					printProgress(name, written, totalSize, start)
					fmt.Fprintln(os.Stderr) // newline after progress
				}
				return written, nil // EOF is expected, not an error
			}
			return written, er
		}
	}
}

// printProgress writes a single-line progress report to stderr.
func printProgress(name string, written, total int64, start time.Time) {
	elapsed := time.Since(start).Seconds()
	if elapsed < 0.1 {
		return
	}
	speed := float64(written) / elapsed
	base := filepath.Base(name)

	if total > 0 {
		pct := float64(written) / float64(total) * 100
		remaining := total - written
		var eta string
		if speed > 0 {
			etaSec := float64(remaining) / speed
			eta = formatDuration(etaSec)
		} else {
			eta = "—"
		}
		fmt.Fprintf(os.Stderr, "\r  %s: %s / %s (%.0f%%) | %s/s | ETA: %s   ",
			base, formatBytes(written), formatBytes(total), pct,
			formatBytes(int64(speed)), eta)
	} else {
		fmt.Fprintf(os.Stderr, "\r  %s: %s | %s/s   ",
			base, formatBytes(written), formatBytes(int64(speed)))
	}
}

// formatDuration turns seconds into a human-readable duration string.
func formatDuration(sec float64) string {
	if sec < 60 {
		return fmt.Sprintf("%.0fs", sec)
	}
	m := int(sec) / 60
	s := int(sec) % 60
	return fmt.Sprintf("%dm%ds", m, s)
}

// checkDiskSpace is implemented in disk_unix.go / disk_windows.go (build-tagged).

// ---------------------------------------------------------------------------
// File processing (encrypt / decrypt)
// ---------------------------------------------------------------------------

func processOne(srcPath, dstPath string, f *flags, command string) (int64, error) {
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return 0, fmt.Errorf("stat source: %w", err)
	}
	fileSize := srcInfo.Size()

	in, err := os.Open(srcPath)
	if err != nil {
		return 0, fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return 0, fmt.Errorf("create output dir: %w", err)
	}

	out, err := os.Create(dstPath)
	if err != nil {
		return 0, fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	buf := make([]byte, 512*1024)
	showProgress := shouldShowProgress(fileSize, f.verbose)

	if fileSize > 1<<30 { // > 1 GiB
		encTypeForWarn := f.encType
		if command == "dec" && (encTypeForWarn == "auto" || encTypeForWarn == "") {
			// For decrypt, we don't know the type yet — check after detection
		} else if encTypeForWarn == "rc4md5" {
			warnf("Warning: RC4-MD5 is ~10-50x slower than AES-CTR/ChaCha20.\n"+
				"  For a %s file, expect ~%s on a single core. Consider -t aesctr or -t chacha20.\n",
				formatBytes(fileSize), formatDuration(float64(fileSize)/30/1024/1024))
		}
	}

	if command == "enc" {
		enc, err := encryption.NewLatestContentEncryptor(f.password, f.encType, fileSize)
		if err != nil {
			return 0, fmt.Errorf("create encryptor: %w", err)
		}
		reader, err := enc.EncryptReader(in, 0)
		if err != nil {
			return 0, fmt.Errorf("encrypt reader: %w", err)
		}
		return copyWithProgress(out, reader, buf, fileSize, srcPath, showProgress)
	}

	// Decrypt: determine encType (auto-detect if not specified)
	encType := f.encType
	detectMethod := "user-specified"
	if encType == "auto" || encType == "" {
		var t encryption.EncType
		t, detectMethod = detectEncTypeVerbose(srcPath, f.password)
		encType = string(t)
	}

	if detectMethod == "default" {
		// All detection methods failed — the file might use a non-aesctr
		// algorithm.  Warn the user so they can try -t explicitly.
		warnf("Warning: could not auto-detect encryption type for %s\n"+
			"  (no V2 header, filename CRC6 failed, no recognized file signature)\n"+
			"  Defaulting to aesctr. If the output is corrupt, try: -t chacha20 or -t rc4md5\n",
			filepath.Base(srcPath))
	}

	// RC4-MD5 warning for decrypt mode (encType known after detection)
	if fileSize > 1<<30 && encType == "rc4md5" {
		warnf("Warning: RC4-MD5 is ~10-50x slower than AES-CTR/ChaCha20.\n"+
			"  For a %s file, expect ~%s on a single core.\n",
			formatBytes(fileSize), formatDuration(float64(fileSize)/30/1024/1024))
	}

	logf(f.verbose, "  detected: %s via %s\n", encType, detectMethod)

	// AutoDecryptReader handles V1/V2 header detection automatically
	reader, _, err := encryption.AutoDecryptReader(f.password, encryption.EncType(encType), in, fileSize)
	if err != nil {
		return 0, fmt.Errorf("create decryptor: %w", err)
	}
	return copyWithProgress(out, reader, buf, fileSize, srcPath, showProgress)
}

// ---------------------------------------------------------------------------
// Post-encryption verification
// ---------------------------------------------------------------------------

// verifyEncryption reads back the first verifySampleSize bytes of the encrypted
// file, decrypts them, and compares with the original. This catches password
// mismatches and algorithm errors early before uploading to Alist.
func verifyEncryption(origPath, encPath string, f *flags) error {
	origFile, err := os.Open(origPath)
	if err != nil {
		return fmt.Errorf("open original for verify: %w", err)
	}
	defer origFile.Close()

	encFile, err := os.Open(encPath)
	if err != nil {
		return fmt.Errorf("open encrypted for verify: %w", err)
	}
	defer encFile.Close()

	// Read original sample
	origSample := make([]byte, verifySampleSize)
	origN, err := io.ReadFull(origFile, origSample)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("read original: %w", err)
	}
	if origN == 0 {
		return nil // empty file, nothing to verify
	}
	origSample = origSample[:origN]

	// Decrypt encrypted sample
	encSample := make([]byte, verifySampleSize)
	encN, err := io.ReadFull(encFile, encSample)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("read encrypted: %w", err)
	}
	encSample = encSample[:encN]

	// AutoDecryptReader reads the V2 header (32 bytes) first, then decrypts.
	// So we need at least 32 + 1 bytes to verify anything meaningful.
	if encN < 33 {
		return nil // too small to verify meaningfully
	}

	reader, _, err := encryption.AutoDecryptReader(
		f.password, encryption.EncType(f.encType),
		bytes.NewReader(encSample), int64(encN),
	)
	if err != nil {
		return fmt.Errorf("decrypt for verify: %w", err)
	}

	decrypted := make([]byte, origN)
	decN, err := io.ReadFull(reader, decrypted)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return fmt.Errorf("read decrypted: %w", err)
	}
	decrypted = decrypted[:decN]

	if !bytes.Equal(origSample[:decN], decrypted) {
		return fmt.Errorf("decrypted sample does not match original (got %d bytes, expected %d)", decN, origN)
	}

	return nil
}

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

func parseFlags(command string) *flags {
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	f := &flags{}

	fs.StringVar(&f.password, "p", "", "encryption password (required)")
	fs.StringVar(&f.password, "password", "", "encryption password (required)")
	fs.StringVar(&f.passwordFile, "password-file", "", "read password from file (safer for scripts; mutually exclusive with --password)")
	fs.StringVar(&f.input, "i", "", "input file or directory (required)")
	fs.StringVar(&f.input, "input", "", "input file or directory (required)")
	fs.StringVar(&f.output, "o", "", "output path (default: alongside source)")
	fs.StringVar(&f.output, "output", "", "output path")
	fs.StringVar(&f.encType, "t", "auto", "algorithm: aesctr (enc default) | chacha20 | rc4md5 | auto (dec default)")
	fs.StringVar(&f.encType, "type", "auto", "algorithm: aesctr | chacha20 | rc4md5 | auto")
	fs.BoolVar(&f.encName, "n", false, "enc: encrypt filenames")
	fs.BoolVar(&f.encName, "enc-name", false, "enc: encrypt filenames")
	fs.StringVar(&f.suffix, "s", ".bin", `enc: suffix (default .bin, "" = none)`)
	fs.StringVar(&f.suffix, "suffix", ".bin", "enc: suffix to append")
	fs.IntVar(&f.workers, "w", 0, "parallel workers for batch (default: NumCPU)")
	fs.IntVar(&f.workers, "workers", 0, "parallel workers for batch (default: NumCPU)")
	fs.BoolVar(&f.verbose, "v", false, "verbose output")
	fs.BoolVar(&f.verbose, "verbose", false, "verbose output")
	fs.StringVar(&f.logFile, "log", "", "write detailed error log to this file")

	_ = fs.Parse(os.Args[2:])
	return f
}

// loadPassword resolves the password source after flag parsing.
//
// Password files commonly end with one editor-added newline. Remove exactly
// one trailing LF or CRLF while preserving every other byte, including leading
// and trailing spaces that may intentionally be part of the password.
func loadPassword(f *flags) error {
	if f.password != "" && f.passwordFile != "" {
		return fmt.Errorf("--password and --password-file are mutually exclusive")
	}
	if f.passwordFile == "" {
		if f.password == "" {
			return fmt.Errorf("-p/--password or --password-file is required")
		}
		return nil
	}

	data, err := os.ReadFile(f.passwordFile)
	if err != nil {
		return fmt.Errorf("read password file: %w", err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return fmt.Errorf("password file contains a NUL byte")
	}
	if bytes.HasSuffix(data, []byte("\r\n")) {
		data = data[:len(data)-2]
	} else if bytes.HasSuffix(data, []byte("\n")) {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return fmt.Errorf("password file is empty")
	}

	f.password = string(data)
	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `encrypt-tool %s - Standalone file encryption/decryption CLI

Files encrypted by this tool are fully compatible with the alist-encrypt-go proxy
for online decryption and video playback (Range seek supported).

Usage:
  encrypt-tool <command> [flags]

Commands:
  enc    Encrypt file(s) or directory
  dec    Decrypt file(s) — fully automatic (V1/V2, type, suffix, filename)

Encrypt flags:
  -p, --password <str>   Password (mutually exclusive with --password-file)
      --password-file <path>
                         Read password from file (recommended for scripts)
  -i, --input <path>     Input file or directory (required)
  -o, --output <path>    Output path (default: alongside source)
  -t, --type <algo>      aesctr (default) | chacha20 | rc4md5
  -n, --enc-name         Encrypt filenames (matches proxy's ConvertRealNameWithSuffix)
  -s, --suffix <str>     Encrypted suffix (default: .bin, "" = none)
  -w, --workers <n>      Parallel workers for batch (default: NumCPU)
      --log <path>       Write detailed error log to file

Decrypt flags:
  -p, --password <str>   Password (mutually exclusive with --password-file)
      --password-file <path>
                         Read password from file (recommended for scripts)
  -i, --input <path>     Input file or directory (required)
  -o, --output <path>    Output path (default: alongside source)
  -t, --type <algo>      auto (default) | aesctr | chacha20 | rc4md5
  -w, --workers <n>      Parallel workers for batch (default: NumCPU)
  -v, --verbose          Show progress per file
      --log <path>       Write detailed error log (detection, warnings, errors)

Decrypt auto-detection:
  - V1/V2:     Auto-detected from file header (V2 has 32-byte header)
  - Type:      Auto-detected from V2 magic bytes (AECTR2/CHC202/RC4MD2)
               V1 fallback cascade: filename CRC6 → content file signature → aesctr
  - Suffix:    .bin/.enc/.dat always stripped; others detected via CRC6
  - Filename:  Auto-decrypted if CRC6 verification passes

Verification:
  After encryption, the first 4KB is read back and decrypted to verify
  correctness. This catches password/algorithm issues before upload.

Examples:
  # Read password from a protected file (recommended for automation)
  encrypt-tool enc --password-file /etc/encrypted-mover/key -i oceans.mp4

  # Encrypt single file → oceans.mp4.bin
  encrypt-tool enc -p mypass -i oceans.mp4

  # Batch encrypt folder with filename encryption (4 workers)
  encrypt-tool enc -p mypass -i ./videos -o ./encrypted -n -w 4

  # Decrypt — just the password, everything else is automatic
  encrypt-tool dec -p mypass -i oceans.mp4.bin
  encrypt-tool dec -p mypass -i ./encrypted -o ./decrypted -v -w 4

  # Use chacha20 for encryption
  encrypt-tool enc -p mypass -i file.zip -t chacha20

  # No suffix
  encrypt-tool enc -p mypass -i file.zip -s ""

  # Batch decrypt with error log for troubleshooting
  encrypt-tool dec -p mypass -i ./encrypted -o ./decrypted --log errors.log -v -w 4
`, version)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func opName(command string) string {
	if command == "enc" {
		return "encrypt"
	}
	return "decrypt"
}

func logf(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, format, args...)
	}
	if logHandle != nil {
		logLine(format, args...)
	}
}

// logLine writes a timestamped line to the log file (if --log was used).
func logLine(format string, args ...interface{}) {
	if logHandle == nil {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(logHandle, "[%s] %s\n", ts, strings.TrimRight(msg, "\n"))
}

// warnf prints a warning to stderr and the log file.
func warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	if logHandle != nil {
		msg := fmt.Sprintf(format, args...)
		msg = strings.TrimPrefix(msg, "Warning: ")
		logLine("WARNING: %s", strings.TrimRight(msg, "\n"))
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	if logHandle != nil {
		logLine("FATAL: %s", msg)
		logHandle.Close()
	}
	os.Exit(1)
}
