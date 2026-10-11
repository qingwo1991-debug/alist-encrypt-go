package encryption

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestOrigMarkerOnPasswordMismatch demonstrates why a file whose encrypted
// filename was created under one password shows up as "orig_<name>" (or can't
// be name-decoded) when another alist-encrypt instance (e.g. the docker image)
// is configured with a DIFFERENT password for the same storage path.
//
// Root cause of "为什么 docker alist-encrypt 没办法解密": filename decode is
// password + encType + encSuffix sensitive. If the storage was written by the
// mobile app proxy (password A) but the docker/desktop proxy serves the same
// path with password B, then:
//   - DecodeName under B fails the CRC6 check → display name falls back to
//     the "orig_" marker (ConvertShowNameWithSuffixOptions returns
//     OrigPrefix+fileName at filename.go), so the cloud shows a cryptic
//     orig_93k...bin filename.
//   - The content header (V2) is keyed to decryption with PBKDF2(password, ...).
//     Password B produces a different per-file key, so the plain bytes do not
//     match the header either → the proxy cannot return the original plaintext.
func TestOrigMarkerOnPasswordMismatch(t *testing.T) {
	const passwordA = "correct-horse-battery-staple"
	const passwordB = "different-password-value"

	original := "movie.mp4"
	encName := ConvertRealNameWithSuffix(passwordA, "aesctr", original, ".bin")
	if encName == "" {
		t.Fatal("empty encrypted name")
	}
	t.Logf("store name (password A): %s", encName)

	// Same password must decode to the original name (no orig_ marker).
	showA := ConvertShowNameWithSuffixOptions(passwordA, "aesctr", encName, ".bin", false)
	if showA != original {
		t.Fatalf("same-password decode = %q, want %q", showA, original)
	}

	// Different password → decode fails → the proxy returns the orig_ marker
	// as the *display* name (and cannot re-encode the path for content DNA).
	showB := ConvertShowNameWithSuffixOptions(passwordB, "aesctr", encName, ".bin", false)
	if !strings.HasPrefix(showB, OrigPrefix) {
		t.Fatalf("password mismatch should surface as orig_ marker, got %q", showB)
	}
	if direct := DecodeName(passwordB, "aesctr", strings.TrimSuffix(encName, ".bin")); direct != "" {
		t.Fatalf("DecodeName under wrong password should be empty, got %q", direct)
	}
}

// TestSamePasswordNameMangledStillShowsOrig proves that with the *exact same*
// password, a single file whose stored name is no longer byte-identical to what
// EncodeName produced (renamed/mangled/truncated during migration) fails
// DecodeName → shows the orig_ marker. This is the per-file case the user hit:
// directory config is correct (that's why Linux sibling files decode), only the
// file's own name lost its CRC validity.
func TestSamePasswordNameMangledStillShowsOrig(t *testing.T) {
	const password = "the-same-password-everywhere"

	original := "IMG_20240922_183045_很长的中文文件名示例.jpg"
	encName := ConvertRealNameWithSuffix(password, "aesctr", original, ".bin")
	if encName == "" {
		t.Fatal("empty encrypted name")
	}

	// 1. Clean name round-trips fine with the SAME password.
	show := ConvertShowNameWithSuffixOptions(password, "aesctr", encName, ".bin", false)
	if show != original {
		t.Fatalf("clean name decode = %q, want %q", show, original)
	}

	// 2. A single corrupted char mid-name (migration renamed/mangled one byte)
	//    kills the CRC6 check deterministically (a trailing-char flip is only
	//    1/64 coincidental, a middle flip always fails).
	mid := len(encName) / 2
	flip := byte('A')
	if encName[mid] == 'A' {
		flip = 'B'
	}
	mangled := encName[:mid] + string(flip) + encName[mid+1:]
	showM := ConvertShowNameWithSuffixOptions(password, "aesctr", mangled, ".bin", false)
	if !strings.HasPrefix(showM, OrigPrefix) {
		t.Fatalf("mangled (%q) should fall back to orig_ marker, got %q", mangled, showM)
	}

	// 3. Truncation of the stored name also kills the name lookup. Cut into
	//    the encrypted payload (beyond the ".bin" suffix) so the CRC char and
	//    several payload chars are gone.
	truncated := encName[:len(encName)-len(".bin")-3]
	if len(truncated) < 4 {
		t.Fatal("test name too short to truncate")
	}
	showT := ConvertShowNameWithSuffixOptions(password, "aesctr", truncated, ".bin", false)
	if !strings.HasPrefix(showT, OrigPrefix) {
		t.Fatalf("truncated name (%q) should fall back to orig_ marker, got %q", truncated, showT)
	}
}

// TestOrigNamePersistedOnDiskAsLiteral covers the migration reality: the raw
// storage holds a file LITERALLY named "orig_<...>.bin" (an earlier proxy listed
// it as an orig_ marker and the name was copied as-is). A name byte-equal to
// "orig_" + ciphertext is NOT a valid encrypted name (DecodeName fails on the
// full string), so ConvertShowName keeps/gives it the orig_ display and
// resolveEncryptedPath strips the prefix → the remainder is treated as a real
// (ungenerated) path. Content streaming may still decode via header probing,
// but the friendly name is permanently unavailable.
func TestOrigNamePersistedOnDiskAsStorageLiteral(t *testing.T) {
	const password = "same-password-copy-of-listing"

	original := "aurora.jpg"
	stored := "orig_" + ConvertRealNameWithSuffix(password, "aesctr", original, ".bin")
	t.Logf("storage literal (as copied from an orig_ listing): %s", stored)

	// DecodeName on the full name (including the literal orig_ prefix) must fail.
	full := strings.TrimSuffix(stored, ".bin")
	if out := DecodeName(password, "aesctr", full); out != "" {
		t.Fatalf("literal orig_ name should NOT decode, got %q", out)
	}

	// The display layer keeps/marks it orig_ (it can't recover the plain name).
	show := ConvertShowNameWithSuffixOptions(password, "aesctr", stored, ".bin", false)
	if !strings.HasPrefix(show, OrigPrefix) {
		t.Fatalf("literal orig_ storage name should display as orig_, got %q", show)
	}
}
func TestDecryptWrongPasswordFailsContent(t *testing.T) {
	const passwordA = "alist-encrypt-demo-pass"
	const passwordB = "totally-different-key"

	plain := []byte("the quick brown fox jumps over the lazy dog")

	// Build a V2 container with password A.
	full, err := NewLatestContentEncryptor(passwordA, "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := full.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(enc)
	if err != nil {
		t.Fatal(err)
	}
	meta := full.Meta

	// Trying to decrypt the same container with password B must not yield the
	// original plaintext (the derived key/keystream differs).
	dec, err := NewCipherV2(meta.EncType, passwordB, meta.PlainSize, meta.NonceField)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	dec.Decrypt(out)
	out = out[len(ciphertext)-len(plain):] // strip the V2 header
	if string(out) == string(plain) {
		t.Fatal("password B should NOT decrypt password A container")
	}
}
