package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/pbkdf2"
)

const (
	ContentVersionV1 = 1
	ContentVersionV2 = 2

	pbkdf2IterationsModern = 600000

	contentHeaderMagicLen = 6
	contentHeaderSize     = 32
	contentHeaderReserved = 0
)

var contentHeaderMagic = map[EncryptionType]string{
	EncTypeAESCTR:   "AECTR2",
	EncTypeChaCha20: "CHC202",
	EncTypeRC4:      "RC4MD2",
}

const v2KeyCacheTTL = 30 * time.Minute

type v2KeyCacheEntry struct {
	key      []byte
	expireAt time.Time
}

var (
	v2KeyCache   = make(map[string]v2KeyCacheEntry)
	v2KeyCacheMu sync.RWMutex
)

func cachedV2Key(password, encType string, keyLen int) []byte {
	cacheKey := fmt.Sprintf("%s:%s:%d", password, encType, keyLen)

	v2KeyCacheMu.RLock()
	if entry, ok := v2KeyCache[cacheKey]; ok && time.Now().Before(entry.expireAt) {
		v2KeyCacheMu.RUnlock()
		return append([]byte(nil), entry.key...)
	}
	v2KeyCacheMu.RUnlock()

	key := pbkdf2.Key([]byte(password), []byte(encType), pbkdf2IterationsModern, keyLen, sha256.New)
	result := append([]byte(nil), key...)

	v2KeyCacheMu.Lock()
	v2KeyCache[cacheKey] = v2KeyCacheEntry{
		key:      result,
		expireAt: time.Now().Add(v2KeyCacheTTL),
	}
	v2KeyCacheMu.Unlock()
	return result
}

type ContentMeta struct {
	EncType        EncryptionType
	Version        int
	HeaderLen      int64
	PlainSize      int64
	CiphertextSize int64
	NonceField     []byte
}

type uploadMetaEntry struct {
	Meta      ContentMeta
	ExpiresAt time.Time
}

const uploadMetaTTLSeconds = int64(30 * 60)

func ContentHeaderSize() int64 {
	return contentHeaderSize
}

func LegacyContentMeta(encType EncryptionType, ciphertextSize int64) ContentMeta {
	return ContentMeta{
		EncType:        normalizeContentEncType(encType),
		Version:        ContentVersionV1,
		HeaderLen:      0,
		PlainSize:      ciphertextSize,
		CiphertextSize: ciphertextSize,
	}
}

func (m ContentMeta) IsV2() bool {
	return m.Version == ContentVersionV2
}

func (m ContentMeta) UpstreamOffset(plainOffset int64) int64 {
	if !m.IsV2() {
		return plainOffset
	}
	return m.HeaderLen + plainOffset
}

func (m ContentMeta) TotalCiphertextSize() int64 {
	if m.CiphertextSize > 0 {
		return m.CiphertextSize
	}
	if m.IsV2() && m.PlainSize > 0 {
		return m.PlainSize + m.HeaderLen
	}
	return m.PlainSize
}

func normalizeContentEncType(encType EncryptionType) EncryptionType {
	switch strings.ToLower(string(encType)) {
	case "", "aesctr", "aes-ctr":
		return EncTypeAESCTR
	case "rc4", "rc4md5":
		return EncTypeRC4
	case "chacha", "chacha20":
		return EncTypeChaCha20
	default:
		return encType
	}
}

func generateRandomNonceField() ([]byte, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func BuildV2Header(encType EncryptionType, plainSize int64, nonceField []byte) ([]byte, error) {
	encType = normalizeContentEncType(encType)
	magic, ok := contentHeaderMagic[encType]
	if !ok {
		return nil, fmt.Errorf("unsupported v2 content header encType: %s", encType)
	}
	if plainSize <= 0 {
		return nil, fmt.Errorf("plain size must be positive")
	}
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	header := make([]byte, contentHeaderSize)
	copy(header[:contentHeaderMagicLen], []byte(magic))
	header[6] = byte(ContentVersionV2)
	header[7] = contentHeaderReserved
	copy(header[8:24], nonceField)
	binary.BigEndian.PutUint64(header[24:32], uint64(plainSize))
	return header, nil
}

func ParseContentHeader(encType EncryptionType, prefix []byte, ciphertextSize int64) (ContentMeta, bool, error) {
	encType = normalizeContentEncType(encType)
	meta := LegacyContentMeta(encType, ciphertextSize)
	if len(prefix) < contentHeaderMagicLen {
		return meta, false, nil
	}
	magic, ok := contentHeaderMagic[encType]
	if !ok || !bytes.Equal(prefix[:contentHeaderMagicLen], []byte(magic)) {
		return meta, false, nil
	}
	if len(prefix) < contentHeaderSize {
		return meta, false, fmt.Errorf("incomplete v2 content header")
	}
	version := int(prefix[6])
	if version != ContentVersionV2 {
		return meta, false, fmt.Errorf("unsupported content version: %d", version)
	}
	plainSize := int64(binary.BigEndian.Uint64(prefix[24:32]))
	if plainSize <= 0 {
		return meta, false, fmt.Errorf("invalid plaintext size in content header")
	}
	nonceField := append([]byte(nil), prefix[8:24]...)
	meta = ContentMeta{
		EncType:        encType,
		Version:        ContentVersionV2,
		HeaderLen:      contentHeaderSize,
		PlainSize:      plainSize,
		CiphertextSize: ciphertextSize,
		NonceField:     nonceField,
	}
	if meta.CiphertextSize <= 0 {
		meta.CiphertextSize = meta.PlainSize + meta.HeaderLen
	}
	return meta, true, nil
}

func NewAESCTRV2(password string, plainSize int64, nonceField []byte) (*AESCTREncryptor, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	key := cachedV2Key(password, "AES-CTR-v2", 16)
	iv := append([]byte(nil), nonceField...)
	sourceIv := append([]byte(nil), iv...)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	return &AESCTREncryptor{
		key:      key,
		iv:       iv,
		sourceIv: sourceIv,
		position: 0,
		cipher:   stream,
		block:    block,
		skipBuf:  make([]byte, 16),
	}, nil
}

func NewChaCha20V2(password string, plainSize int64, nonceField []byte) (*ChaCha20Encryptor, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	key := cachedV2Key(password, "ChaCha20-v2", 32)
	nonce := append([]byte(nil), nonceField[:12]...)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}
	return &ChaCha20Encryptor{
		key:      key,
		nonce:    nonce,
		cipher:   c,
		position: 0,
	}, nil
}

func NewRC4MD5V2(password string, plainSize int64, nonceField []byte) (*RC4MD5Encryptor, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	baseKey := cachedV2Key(password, "RC4-v2", 16)
	material := append(append([]byte(nil), baseKey...), nonceField...)
	rc4KeyHex := hex.EncodeToString(md5sum(material))
	rc4 := &CustomRC4{
		fileHexKey:    rc4KeyHex,
		position:      0,
		stateCache:    make(map[int64]*RC4StateCache),
		cacheInterval: 256 * 1024,
	}
	rc4.resetKSA()
	return &RC4MD5Encryptor{customRC4: rc4}, nil
}

func NewCipherV2(encType EncryptionType, password string, plainSize int64, nonceField []byte) (FlowEncryptor, error) {
	switch normalizeContentEncType(encType) {
	case EncTypeAESCTR:
		return NewAESCTRV2(password, plainSize, nonceField)
	case EncTypeRC4:
		return NewRC4MD5V2(password, plainSize, nonceField)
	case EncTypeChaCha20:
		return NewChaCha20V2(password, plainSize, nonceField)
	case "":
		return NewAESCTRV2(password, plainSize, nonceField)
	default:
		return nil, fmt.Errorf("unsupported v2 encryption type: %s", encType)
	}
}

type ContentEncryptor struct {
	Cipher FlowEncryptor
	Meta   ContentMeta
	Header []byte
}

func NewLatestContentEncryptor(password, encType string, plainSize int64) (*ContentEncryptor, error) {
	normalized := normalizeContentEncType(EncryptionType(encType))
	if normalized == "" {
		normalized = EncTypeAESCTR
	}
	nonceField, err := generateRandomNonceField()
	if err != nil {
		return nil, err
	}
	meta := ContentMeta{
		EncType:        normalized,
		Version:        ContentVersionV2,
		HeaderLen:      contentHeaderSize,
		PlainSize:      plainSize,
		CiphertextSize: plainSize + contentHeaderSize,
		NonceField:     nonceField,
	}
	header, err := BuildV2Header(normalized, plainSize, nonceField)
	if err != nil {
		return nil, err
	}
	cipherImpl, err := NewCipherV2(normalized, password, plainSize, nonceField)
	if err != nil {
		return nil, err
	}
	return &ContentEncryptor{Cipher: cipherImpl, Meta: meta, Header: header}, nil
}

func (e *ContentEncryptor) EncryptReader(r io.Reader, startOffset int64) (io.Reader, error) {
	if e == nil || e.Cipher == nil {
		return nil, fmt.Errorf("content encryptor is nil")
	}
	if startOffset < 0 {
		return nil, fmt.Errorf("start offset cannot be negative")
	}
	if startOffset > 0 {
		if err := e.Cipher.SetPosition(startOffset); err != nil {
			return nil, err
		}
		return NewEncryptReader(r, e.Cipher), nil
	}
	return io.MultiReader(bytes.NewReader(e.Header), NewEncryptReader(r, e.Cipher)), nil
}

func AutoDecryptReader(password string, encType EncryptionType, ciphertext io.Reader, ciphertextSize int64) (io.Reader, ContentMeta, error) {
	encType = normalizeContentEncType(encType)
	if encType == "" {
		encType = EncTypeAESCTR
	}
	prefix := make([]byte, contentHeaderSize)
	n, err := io.ReadFull(ciphertext, prefix)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			prefix = prefix[:n]
		} else {
			return nil, ContentMeta{}, err
		}
	}
	meta, ok, err := ParseContentHeader(encType, prefix, ciphertextSize)
	if err != nil {
		return nil, ContentMeta{}, err
	}
	if ok {
		cipherImpl, err := NewCipherV2(encType, password, meta.PlainSize, meta.NonceField)
		if err != nil {
			return nil, ContentMeta{}, err
		}
		return NewDecryptReader(ciphertext, cipherImpl), meta, nil
	}
	legacy := io.MultiReader(bytes.NewReader(prefix[:n]), ciphertext)
	cipherImpl, err := NewFlowEncryptor(password, encType, ciphertextSize)
	if err != nil {
		return nil, ContentMeta{}, err
	}
	return NewDecryptReader(legacy, cipherImpl), meta, nil
}

func md5sum(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}

func buildUpstreamRangeHeader(rangeHeader string, meta ContentMeta) string {
	if !meta.IsV2() {
		return rangeHeader
	}
	rangeHeader = strings.TrimSpace(rangeHeader)
	if rangeHeader == "" || !strings.HasPrefix(rangeHeader, "bytes=") {
		return rangeHeader
	}
	parts := strings.SplitN(strings.TrimPrefix(rangeHeader, "bytes="), ",", 2)
	if len(parts) == 0 {
		return rangeHeader
	}
	spec := strings.TrimSpace(parts[0])
	bounds := strings.SplitN(spec, "-", 2)
	if len(bounds) != 2 {
		return rangeHeader
	}
	startText := strings.TrimSpace(bounds[0])
	endText := strings.TrimSpace(bounds[1])
	if startText == "" {
		return rangeHeader
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 {
		return rangeHeader
	}
	start += meta.HeaderLen
	if endText == "" {
		return fmt.Sprintf("bytes=%d-", start)
	}
	end, err := strconv.ParseInt(endText, 10, 64)
	if err != nil || end < start-meta.HeaderLen {
		return rangeHeader
	}
	end += meta.HeaderLen
	return fmt.Sprintf("bytes=%d-%d", start, end)
}

func rewritePlainContentRangeToCiphertext(contentRange string, headerLen int64) (string, bool) {
	contentRange = strings.TrimSpace(contentRange)
	if contentRange == "" || headerLen <= 0 {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(contentRange), "bytes ") {
		return "", false
	}
	spec := strings.TrimSpace(contentRange[len("bytes "):])
	slash := strings.Index(spec, "/")
	if slash <= 0 {
		return "", false
	}
	rangePart := strings.TrimSpace(spec[:slash])
	totalPart := strings.TrimSpace(spec[slash+1:])
	parts := strings.SplitN(rangePart, "-", 2)
	if len(parts) != 2 {
		return "", false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return "", false
	}
	end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil || end < start {
		return "", false
	}
	total, err := strconv.ParseInt(totalPart, 10, 64)
	if err != nil || total <= 0 {
		return "", false
	}
	return fmt.Sprintf("bytes %d-%d/%d", start+headerLen, end+headerLen, total+headerLen), true
}

func rewriteUploadHeadersForV2(req *http.Request, meta ContentMeta, startOffset int64, originalContentRange string) {
	if req == nil || !meta.IsV2() {
		return
	}
	ciphertextSize := meta.TotalCiphertextSize()
	if rewritten, ok := rewritePlainContentRangeToCiphertext(originalContentRange, meta.HeaderLen); ok {
		req.Header.Set("Content-Range", rewritten)
	}
	if req.ContentLength > 0 {
		if startOffset == 0 {
			req.ContentLength += meta.HeaderLen
		}
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	if ciphertextSize > 0 {
		sizeStr := strconv.FormatInt(ciphertextSize, 10)
		req.Header.Set("X-File-Size", sizeStr)
		req.Header.Set("File-Size", sizeStr)
		req.Header.Set("X-Upload-Content-Length", sizeStr)
		req.Header.Set("X-Expected-Entity-Length", sizeStr)
	}
}

func parseContentRangeTotal(contentRange string) int64 {
	if contentRange == "" {
		return 0
	}
	if idx := strings.LastIndex(contentRange, "/"); idx >= 0 && idx+1 < len(contentRange) {
		totalStr := contentRange[idx+1:]
		if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil {
			return total
		}
	}
	return 0
}

func discardBytes(r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, n)
	return err
}

func normalizePlainFileSize(fileSize int64, meta *ContentMeta, contentRange string) int64 {
	if meta == nil {
		return fileSize
	}
	if total := parseContentRangeTotal(contentRange); total > 0 {
		if meta.IsV2() {
			meta.CiphertextSize = total
			if total > meta.HeaderLen {
				meta.PlainSize = total - meta.HeaderLen
				return meta.PlainSize
			}
		}
		if fileSize == 0 || total != fileSize {
			fileSize = total
		}
	}
	if meta.IsV2() {
		if meta.CiphertextSize == 0 && fileSize > 0 {
			meta.CiphertextSize = fileSize
		}
		if meta.PlainSize <= 0 && meta.CiphertextSize > meta.HeaderLen {
			meta.PlainSize = meta.CiphertextSize - meta.HeaderLen
		}
		if meta.PlainSize > 0 {
			return meta.PlainSize
		}
		return fileSize
	}
	if meta.PlainSize == 0 {
		meta.PlainSize = fileSize
	}
	return fileSize
}
