// Package main provides a standalone CLI tool for encrypting/decrypting files.
//
//	encrypt-tool enc -p <password> -i <input> [-o output] [-t aesctr] [-n] [-s .bin] [-w 4] [-v]
//	encrypt-tool dec -p <password> -i <input> [-o output] [-w 4] [-v]
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
	"strings"
	"sync"
	"sync/atomic"

	"github.com/alist-encrypt-go/internal/encryption"
)

const version = "1.0.0"

// verifySampleSize is how many bytes we read back after encryption to verify correctness.
const verifySampleSize = 4096

// knownSuffixes are always safe to strip during decryption.
var knownSuffixes = []string{".bin", ".enc", ".dat"}

// allEncTypes is tried in order when auto-detecting from V1 files.
var allEncTypes = []string{"aesctr", "chacha20", "rc4md5"}

// flags holds all parsed command-line options.
type flags struct {
	password string
	input    string
	output   string
	encType  string // "auto" for dec; "aesctr"/"chacha20"/"rc4md5" for enc
	encName  bool   // enc only: encrypt filenames
	suffix   string // enc only: suffix to append
	workers  int    // parallel workers for batch mode
	verbose  bool
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

	if command == "enc" && f.encType == "auto" {
		f.encType = "aesctr"
	}
	if f.workers < 1 {
		f.workers = 1
	}

	if f.password == "" {
		fatal("-p/--password is required")
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
				mu.Lock()
				errMsgs = append(errMsgs, fmt.Sprintf("  %s: %v", j.srcPath, err))
				mu.Unlock()
			} else if command == "enc" {
				if vErr := verifyEncryption(j.srcPath, j.outFile, f); vErr != nil {
					mu.Lock()
					errMsgs = append(errMsgs, fmt.Sprintf("  %s: verification failed: %v", j.srcPath, vErr))
					mu.Unlock()
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
		if baseDir != "" {
			return filepath.Join(baseDir, outRel), false
		}
		return filepath.Join(filepath.Dir(srcPath), outName), false
	}

	outInfo, err := os.Stat(f.output)
	if err == nil && !outInfo.IsDir() && baseDir == "" {
		return f.output, false
	}

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

// encryptOutputName produces the encrypted filename.
//
// With filename encryption (-n):
//   EncodeName(password, encType, fullFileName) + suffix
//   This matches the proxy's ConvertRealNameWithSuffix exactly.
//
// Without filename encryption:
//   originalFileName + suffix
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

	// Step 1: Try decoding the filename as-is (no suffix stripping)
	if decoded := tryDecodeName(fileName, f.password, encType); decoded != "" {
		return decoded
	}

	// Step 2: Try stripping known encrypted suffixes (.bin, .enc, .dat)
	for _, s := range knownSuffixes {
		if strings.HasSuffix(fileName, s) {
			stripped := strings.TrimSuffix(fileName, s)
			if decoded := tryDecodeName(stripped, f.password, encType); decoded != "" {
				return decoded
			}
			// Filename isn't encrypted — return without the suffix
			return stripped
		}
	}

	// Step 3: Try stripping last extension as a potential custom suffix.
	// Only accept if decode succeeds — otherwise it's a real file extension.
	lastExt := filepath.Ext(fileName)
	if lastExt != "" {
		stripped := strings.TrimSuffix(fileName, lastExt)
		if decoded := tryDecodeName(stripped, f.password, encType); decoded != "" {
			return decoded
		}
	}

	// Step 4: No decode worked — filename wasn't encrypted
	return fileName
}

// tryDecodeName splits name into base + extension, tries DecodeName(base).
// Returns the decoded name WITHOUT appending the stripped extension,
// because EncodeName encrypts the full filename (including extension),
// so DecodeName already returns the complete original name.
// This matches the proxy's DecryptPath / ConvertShowName behavior.
func tryDecodeName(name, password, encType string) string {
	ext := filepath.Ext(name)
	baseName := strings.TrimSuffix(name, ext)
	if baseName == "" {
		return ""
	}
	decoded := encryption.DecodeName(password, encType, baseName)
	if decoded != "" {
		return decoded
	}
	return ""
}

// ---------------------------------------------------------------------------
// Encryption type auto-detection
// ---------------------------------------------------------------------------

// detectEncType reads the first 6 bytes to identify V2 encryption type.
// V2 headers contain magic: AECTR2, CHC202, RC4MD2.
// For V1 files (no header), tries filename CRC6 with each type.
// Falls back to aesctr.
func detectEncType(filePath, password string) encryption.EncType {
	header := make([]byte, 6)
	f, err := os.Open(filePath)
	if err != nil {
		return encryption.EncTypeAESCTR
	}
	n, _ := io.ReadFull(f, header)
	f.Close()

	if n >= 6 {
		switch string(header[:6]) {
		case "AECTR2":
			return encryption.EncTypeAESCTR
		case "CHC202":
			return encryption.EncTypeChaCha20
		case "RC4MD2":
			return encryption.EncTypeRC4MD5
		}
	}

	// V1 file: try filename decode with each type
	fileName := filepath.Base(filePath)
	workName := fileName
	for _, s := range knownSuffixes {
		if strings.HasSuffix(workName, s) {
			workName = strings.TrimSuffix(workName, s)
			break
		}
	}
	ext := filepath.Ext(workName)
	baseName := strings.TrimSuffix(workName, ext)

	if baseName != "" {
		for _, t := range allEncTypes {
			if encryption.DecodeName(password, t, baseName) != "" {
				return encryption.EncType(t)
			}
		}
	}

	return encryption.EncTypeAESCTR
}

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

	if command == "enc" {
		enc, err := encryption.NewLatestContentEncryptor(f.password, f.encType, fileSize)
		if err != nil {
			return 0, fmt.Errorf("create encryptor: %w", err)
		}
		reader, err := enc.EncryptReader(in, 0)
		if err != nil {
			return 0, fmt.Errorf("encrypt reader: %w", err)
		}
		return io.CopyBuffer(out, reader, buf)
	}

	// Decrypt: determine encType (auto-detect if not specified)
	encType := f.encType
	if encType == "auto" || encType == "" {
		encType = string(detectEncType(srcPath, f.password))
	}

	// AutoDecryptReader handles V1/V2 header detection automatically
	reader, _, err := encryption.AutoDecryptReader(f.password, encryption.EncType(encType), in, fileSize)
	if err != nil {
		return 0, fmt.Errorf("create decryptor: %w", err)
	}
	return io.CopyBuffer(out, reader, buf)
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
	fs.IntVar(&f.workers, "w", 1, "number of parallel workers for batch mode")
	fs.IntVar(&f.workers, "workers", 1, "number of parallel workers")
	fs.BoolVar(&f.verbose, "v", false, "verbose output")
	fs.BoolVar(&f.verbose, "verbose", false, "verbose output")

	_ = fs.Parse(os.Args[2:])
	return f
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
  -p, --password <str>   Password (required)
  -i, --input <path>     Input file or directory (required)
  -o, --output <path>    Output path (default: alongside source)
  -t, --type <algo>      aesctr (default) | chacha20 | rc4md5
  -n, --enc-name         Encrypt filenames (matches proxy's ConvertRealNameWithSuffix)
  -s, --suffix <str>     Encrypted suffix (default: .bin, "" = none)
  -w, --workers <n>      Parallel workers for batch mode (default: 1)

Decrypt flags:
  -p, --password <str>   Password — the only thing you need
  -i, --input <path>     Input file or directory (required)
  -o, --output <path>    Output path (default: alongside source)
  -t, --type <algo>      auto (default) | aesctr | chacha20 | rc4md5
  -w, --workers <n>      Parallel workers for batch mode (default: 1)
  -v, --verbose          Show progress per file

Decrypt auto-detection:
  - V1/V2:     Auto-detected from file header (V2 has 32-byte header)
  - Type:      Auto-detected from V2 magic bytes (AECTR2/CHC202/RC4MD2)
               V1 fallback: tries filename CRC6, then defaults to aesctr
  - Suffix:    .bin/.enc/.dat always stripped; others detected via CRC6
  - Filename:  Auto-decrypted if CRC6 verification passes

Verification:
  After encryption, the first 4KB is read back and decrypted to verify
  correctness. This catches password/algorithm issues before upload.

Examples:
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
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
