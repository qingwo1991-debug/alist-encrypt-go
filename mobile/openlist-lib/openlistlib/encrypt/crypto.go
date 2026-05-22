package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptionType 加密类型
type EncryptionType string

const (
	EncTypeAESCTR   EncryptionType = "aes-ctr"
	EncTypeRC4      EncryptionType = "rc4md5"
	EncTypeMix      EncryptionType = "mix"
	EncTypeChaCha20 EncryptionType = "chacha20"
)

// 缓存密码外部密钥
var (
	passwdOutwardCache  = make(map[string]string)
	passwdOutwardMu     sync.RWMutex
	showNameDecodeCache sync.Map
)

// CRC6 实例
var crc6 = NewCRC6()

// 外部添加的后缀模式（云盘/同步工具自动添加）
var externalSuffixPatterns = []*regexp.Regexp{
	regexp.MustCompile(`_\d{8}_\d{6}$`),   // _YYYYMMDD_HHMMSS（百度网盘等）
	regexp.MustCompile(` \(\d+\)$`),       // " (1)", " (2)" 等（文件冲突重命名）
	regexp.MustCompile(`\(\d+\)$`),        // "(1)", "(2)" 等（无空格冲突重命名）
	regexp.MustCompile(`_\d+$`),           // _1, _2 等（简单数字后缀）
	regexp.MustCompile(`~q[0-9A-Za-z]+$`), // ~qxxx（部分客户端冲突后缀）
}

// 外部后缀标记常量（用于在显示名中嵌入外部后缀信息）
const (
	suffixMarker    = "{__esuffix__" // external suffix marker start
	suffixMarkerEnd = "}"            // external suffix marker end
)

// ShowNameCache 显示名到真实加密名的缓存
// Key: 目录路径 + 显示名 (如 "/path/to/dir/KBR-008.mp4")
// Value: 真实加密文件名（包含外部后缀，如 "Z3LZ5G0YQxHtage-N (1).mp4"）
type ShowNameCache struct {
	cache sync.Map
	size  int64
}

// 全局显示名缓存实例
var showNameCache = &ShowNameCache{}

// showNameCacheMaxSize 缓存最大条目数
const showNameCacheMaxSize = 50000
const showNameDecodeCacheTTL = 10 * time.Minute

type decodeCacheEntry struct {
	value    string
	expireAt time.Time
}

func showNameDecodeCacheKey(password string, encType EncryptionType, encName string) string {
	return password + "|" + string(encType) + "|" + encName
}

func decodeNameCached(password string, encType EncryptionType, encName string) string {
	key := showNameDecodeCacheKey(password, encType, encName)
	if v, ok := showNameDecodeCache.Load(key); ok {
		if entry, ok := v.(*decodeCacheEntry); ok && time.Now().Before(entry.expireAt) {
			return entry.value
		}
		showNameDecodeCache.Delete(key)
	}
	decoded := DecodeName(password, encType, encName)
	showNameDecodeCache.Store(key, &decodeCacheEntry{
		value:    decoded,
		expireAt: time.Now().Add(showNameDecodeCacheTTL),
	})
	return decoded
}

// CacheNameMapping 缓存显示名到真实加密名的映射
func CacheNameMapping(dir, showName, realEncName string) {
	if showName == "" || realEncName == "" {
		return
	}
	key := path.Join(dir, showName)
	showNameCache.cache.Store(key, realEncName)
	// 简单计数，不精确但足够
	if showNameCache.size < showNameCacheMaxSize {
		showNameCache.size++
	}
}

// GetCachedRealName 从缓存获取真实加密名
func GetCachedRealName(dir, showName string) (string, bool) {
	key := path.Join(dir, showName)
	if val, ok := showNameCache.cache.Load(key); ok {
		return val.(string), true
	}
	return "", false
}

// ClearShowNameCache 清除显示名缓存（用于测试或刷新）
func ClearShowNameCache() {
	showNameCache.cache = sync.Map{}
	showNameCache.size = 0
	showNameDecodeCache = sync.Map{}
}

// stripExternalSuffix 尝试剥离外部添加的后缀，返回剥离后的字符串和剥离的后缀
func stripExternalSuffix(name string) (string, string) {
	for _, pattern := range externalSuffixPatterns {
		if loc := pattern.FindStringIndex(name); loc != nil {
			return name[:loc[0]], name[loc[0]:]
		}
	}
	return name, ""
}

// FlowEncryptor 流加密器接口
type FlowEncryptor interface {
	// Encrypt 加密数据
	Encrypt(data []byte) ([]byte, error)
	// Decrypt 解密数据
	Decrypt(data []byte) ([]byte, error)
	// SetPosition 设置流位置（用于随机访问）
	SetPosition(position int64) error
	// GetPosition 获取当前位置
	GetPosition() int64
}

// InplaceFlowEncryptor 可选的原地加解密接口，用于减少每块分配与拷贝
type InplaceFlowEncryptor interface {
	EncryptInplace(data []byte) error
	DecryptInplace(data []byte) error
}

// AESCTREncryptor AES-CTR 加密器
type AESCTREncryptor struct {
	key      []byte
	iv       []byte
	sourceIv []byte
	position int64
	cipher   cipher.Stream
	block    cipher.Block // 缓存 AES block，避免每次 SetPosition 重建
	skipBuf  []byte       // 复用的 skip 缓冲区
}

// NewAESCTREncryptor 创建 AES-CTR 加密器 (Node.js compatible)
func NewAESCTREncryptor(password, passwdOutward string, fileSize int64) (*AESCTREncryptor, error) {
	sizeSalt := strconv.FormatInt(fileSize, 10)
	passwdSalt := passwdOutward + sizeSalt

	// create file aes-ctr key: md5(passwdSalt)
	hash := md5.Sum([]byte(passwdSalt))
	key := hash[:]

	// iv: md5(sizeSalt)
	hashIv := md5.Sum([]byte(sizeSalt))
	iv := hashIv[:]
	sourceIv := make([]byte, len(iv))
	copy(sourceIv, iv)

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
		block:    block,            // 缓存 block
		skipBuf:  make([]byte, 16), // 预分配 skip 缓冲区（最大 15 字节）
	}, nil
}

// incrementIV 增加 IV
func (e *AESCTREncryptor) incrementIV(increment int64) {
	// copy sourceIv to iv
	iv := make([]byte, len(e.sourceIv))
	copy(iv, e.sourceIv)
	e.iv = iv

	// Match Node.js aesCTR.js incrementIV implementation
	const maxUint32 = uint64(0xffffffff)
	inc := uint64(increment)
	incrementBig := int64(inc / maxUint32)
	incrementLittle := int64(inc%maxUint32) - incrementBig

	overflow := int64(0)
	for idx := 0; idx < 4; idx++ {
		offset := 12 - idx*4
		num := int64(uint32(e.iv[offset])<<24 | uint32(e.iv[offset+1])<<16 | uint32(e.iv[offset+2])<<8 | uint32(e.iv[offset+3]))
		incPart := overflow
		if idx == 0 {
			incPart += incrementLittle
		}
		if idx == 1 {
			incPart += incrementBig
		}
		num += incPart
		numBig := num / int64(maxUint32)
		numLittle := num%int64(maxUint32) - numBig
		overflow = numBig
		v := uint32(numLittle)
		e.iv[offset] = byte(v >> 24)
		e.iv[offset+1] = byte(v >> 16)
		e.iv[offset+2] = byte(v >> 8)
		e.iv[offset+3] = byte(v)
	}
}

// SetPosition 设置流位置
func (e *AESCTREncryptor) SetPosition(position int64) error {
	increment := position / 16
	e.incrementIV(increment)

	// 复用缓存的 block，只重建 CTR stream
	e.cipher = cipher.NewCTR(e.block, e.iv)

	offset := int(position % 16)
	if offset > 0 {
		// 使用预分配的缓冲区，避免内存分配
		e.cipher.XORKeyStream(e.skipBuf[:offset], e.skipBuf[:offset])
	}

	e.position = position
	return nil
}

// GetPosition 获取当前位置
func (e *AESCTREncryptor) GetPosition() int64 {
	return e.position
}

// Encrypt 加密数据
func (e *AESCTREncryptor) Encrypt(data []byte) ([]byte, error) {
	encrypted := make([]byte, len(data))
	e.cipher.XORKeyStream(encrypted, data)
	e.position += int64(len(data))
	return encrypted, nil
}

// Decrypt 解密数据
func (e *AESCTREncryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// EncryptInplace 原地加密，避免每次分配新切片
func (e *AESCTREncryptor) EncryptInplace(data []byte) error {
	e.cipher.XORKeyStream(data, data)
	e.position += int64(len(data))
	return nil
}

// DecryptInplace 原地解密（CTR 对称）
func (e *AESCTREncryptor) DecryptInplace(data []byte) error {
	return e.EncryptInplace(data)
}

// RC4MD5Encryptor RC4-MD5 加密器 (Wrapper for CustomRC4)
type RC4MD5Encryptor struct {
	customRC4 *CustomRC4
}

// NewRC4MD5Encryptor 创建 RC4-MD5 加密器
func NewRC4MD5Encryptor(password, passwdOutward string, fileSize int64) (*RC4MD5Encryptor, error) {
	sizeSalt := strconv.FormatInt(fileSize, 10)
	cRC4 := NewCustomRC4(password, sizeSalt, passwdOutward)
	return &RC4MD5Encryptor{customRC4: cRC4}, nil
}

func (e *RC4MD5Encryptor) SetPosition(position int64) error {
	e.customRC4.SetPosition(position)
	return nil
}

func (e *RC4MD5Encryptor) GetPosition() int64 {
	return e.customRC4.position
}

func (e *RC4MD5Encryptor) Encrypt(data []byte) ([]byte, error) {
	dst := make([]byte, len(data))
	e.customRC4.XORKeyStream(dst, data)
	return dst, nil
}

func (e *RC4MD5Encryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// EncryptInplace 原地加密，避免每次分配新切片
func (e *RC4MD5Encryptor) EncryptInplace(data []byte) error {
	e.customRC4.XORKeyStream(data, data)
	return nil
}

// DecryptInplace 原地解密（RC4 对称）
func (e *RC4MD5Encryptor) DecryptInplace(data []byte) error {
	return e.EncryptInplace(data)
}

// NewFlowEncryptor 创建流加密器
func NewFlowEncryptor(password string, encType EncryptionType, fileSize int64) (FlowEncryptor, error) {
	passwdOutward := GetPasswdOutward(password, encType)
	switch encType {
	case EncTypeAESCTR, "aesctr":
		return NewAESCTREncryptor(password, passwdOutward, fileSize)
	case EncTypeRC4, "rc4":
		return NewRC4MD5Encryptor(password, passwdOutward, fileSize)
	case EncTypeMix:
		return NewMixEncryptor(password, fileSize)
	case EncTypeChaCha20, "chacha":
		return NewChaCha20Encryptor(password, passwdOutward, fileSize)
	default:
		return nil, errors.New("unsupported encryption type: " + string(encType))
	}
}

// GetPasswdOutward 获取外部密码（用于文件名加密）
func GetPasswdOutward(password string, encType EncryptionType) string {
	key := password + string(encType)
	passwdOutwardMu.RLock()
	cached, ok := passwdOutwardCache[key]
	passwdOutwardMu.RUnlock()
	if ok {
		return cached
	}

	var passwdOutward string

	// Logic from Node.js (mixEnc.js, aesCTR.js, rc4Md5.js)
	// If password length != 32, use PBKDF2.
	// Salt depends on encryption type.

	salt := ""
	switch encType {
	case EncTypeMix:
		salt = "MIX"
	case EncTypeAESCTR, "aesctr":
		salt = "AES-CTR"
	case EncTypeRC4, "rc4":
		salt = "RC4"
	case EncTypeChaCha20, "chacha":
		salt = "ChaCha20"
	default:
		// Unknown type, assume password is raw? Or MIX default?
		salt = "MIX"
	}

	if len(password) != 32 {
		keyLen := 16
		if encType == EncTypeChaCha20 || string(encType) == "chacha" {
			keyLen = 32
		}
		dk := pbkdf2.Key([]byte(password), []byte(salt), 1000, keyLen, sha256.New)
		passwdOutward = hex.EncodeToString(dk)
	} else {
		passwdOutward = password
	}

	passwdOutwardMu.Lock()
	passwdOutwardCache[key] = passwdOutward
	passwdOutwardMu.Unlock()
	return passwdOutward
}

// deriveKeyHex is removed as it's no longer used, replaced by PBKDF2 logic inline or verify.

// EncryptReader 加密读取器
type EncryptReader struct {
	reader    io.Reader
	encryptor FlowEncryptor
}

// NewEncryptReader 创建加密读取器
func NewEncryptReader(reader io.Reader, encryptor FlowEncryptor) *EncryptReader {
	return &EncryptReader{
		reader:    reader,
		encryptor: encryptor,
	}
}

// Read 读取并加密数据
func (r *EncryptReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		if inplace, ok := r.encryptor.(InplaceFlowEncryptor); ok {
			if encErr := inplace.EncryptInplace(p[:n]); encErr != nil {
				return 0, encErr
			}
		} else {
			encrypted, encErr := r.encryptor.Encrypt(p[:n])
			if encErr != nil {
				return 0, encErr
			}
			copy(p[:n], encrypted)
		}
	}
	return n, err
}

// DecryptReader 解密读取器
type DecryptReader struct {
	reader    io.Reader
	encryptor FlowEncryptor
}

// NewDecryptReader 创建解密读取器
func NewDecryptReader(reader io.Reader, encryptor FlowEncryptor) *DecryptReader {
	return &DecryptReader{
		reader:    reader,
		encryptor: encryptor,
	}
}

// Read 读取并解密数据
func (r *DecryptReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		if inplace, ok := r.encryptor.(InplaceFlowEncryptor); ok {
			if decErr := inplace.DecryptInplace(p[:n]); decErr != nil {
				return 0, decErr
			}
		} else {
			decrypted, decErr := r.encryptor.Decrypt(p[:n])
			if decErr != nil {
				return 0, decErr
			}
			copy(p[:n], decrypted)
		}
	}
	return n, err
}

// EncodeName 使用 MixBase64 编码文件名（兼容 alist-encrypt）
func EncodeName(password string, encType EncryptionType, plainName string) string {
	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := NewMixBase64(passwdOutward)
	encodeName := mix64.Encode(plainName)
	// 添加 CRC6 校验位
	crc6Bit := crc6.Checksum([]byte(encodeName + passwdOutward))
	crc6Check := MixBase64GetSourceChar(int(crc6Bit))
	result := encodeName + string(crc6Check)
	log.Debugf("[%s] EncodeName: password=%q, encType=%q, plainName=%q -> passwdOutward=%q, encoded=%q, crc6=%d, result=%q",
		internal.TagEncrypt, password, encType, plainName, passwdOutward, encodeName, crc6Bit, result)
	return result
}

// DecodeName 使用 MixBase64 解码文件名（兼容 alist-encrypt）
func DecodeName(password string, encType EncryptionType, encodedName string) string {
	if len(encodedName) < 2 {
		log.Debugf("[%s] DecodeName: encodedName too short: %q", internal.TagDecrypt, encodedName)
		return ""
	}

	crc6Check := encodedName[len(encodedName)-1]
	passwdOutward := GetPasswdOutward(password, encType)

	// 验证 CRC6
	subEncName := encodedName[:len(encodedName)-1]
	crc6Bit := crc6.Checksum([]byte(subEncName + passwdOutward))
	expectedCrc6Check := MixBase64GetSourceChar(int(crc6Bit))
	if expectedCrc6Check != crc6Check {
		log.Debugf("[%s] DecodeName: CRC6 mismatch for %q: expected %c, got %c (passwdOutward=%q)",
			internal.TagDecrypt, encodedName, expectedCrc6Check, crc6Check, passwdOutward)
		return ""
	}

	mix64 := NewMixBase64(passwdOutward)
	decoded, err := mix64.Decode(subEncName)
	if err != nil {
		log.Debugf("[%s] DecodeName: Decode failed for %q: %v", internal.TagDecrypt, subEncName, err)
		return ""
	}

	result := string(decoded)
	log.Debugf("[%s] DecodeName: %q -> %q (passwdOutward=%q)", internal.TagDecrypt, encodedName, result, passwdOutward)
	return result
}

// EncodeFolderName 编码目录名（用于目录级别切换密码/算法）
func EncodeFolderName(password string, encType EncryptionType, folderPasswd string, folderEncType EncryptionType) string {
	passwdInfo := string(folderEncType) + "_" + folderPasswd
	return EncodeName(password, encType, passwdInfo)
}

// DecodeFolderName 解码目录名（返回目录内覆盖的加密配置）
func DecodeFolderName(password string, encType EncryptionType, encodedName string) (EncryptionType, string, bool) {
	arr := strings.Split(encodedName, "_")
	if len(arr) < 2 {
		return "", "", false
	}
	folderEncName := arr[len(arr)-1]
	decodeStr := DecodeName(password, encType, folderEncName)
	if decodeStr == "" {
		return "", "", false
	}
	idx := strings.Index(decodeStr, "_")
	if idx <= 0 || idx >= len(decodeStr)-1 {
		return "", "", false
	}
	folderEncType := EncryptionType(decodeStr[:idx])
	folderPasswd := decodeStr[idx+1:]
	return folderEncType, folderPasswd, true
}

// ConvertRealName 将显示名转换为真实加密名
// 与 alist-encrypt 的 convertRealName 逻辑完全一致：
// - 如果有 orig_ 前缀，去掉前缀返回原名
// - 否则，直接加密文件名（不检查是否已加密）
//
// 注意：alist-encrypt 的设计是：前端总是使用解密后的明文文件名请求，
// 所以 convertRealName 总是需要加密。不应该检测文件名是否"看起来像"已加密，
// 因为解密后的明文可能碰巧通过 CRC 校验。
func ConvertRealName(password string, encType EncryptionType, pathText string) string {
	return ConvertRealNameWithSuffix(password, encType, pathText, "")
}

// ConvertRealNameWithSuffix 将显示名转换为真实加密名，并支持自定义加密后缀
func ConvertRealNameWithSuffix(password string, encType EncryptionType, pathText, encSuffix string) string {
	dir := path.Dir(pathText)
	fileName := path.Base(pathText)
	log.Debugf("[%s] ConvertRealName: pathText=%q, fileName=%q", internal.TagEncrypt, pathText, fileName)

	// 检查是否有 orig_ 前缀（表示原始未加密文件）
	// 这与 alist-encrypt 的行为一致
	if strings.HasPrefix(fileName, "orig_") {
		result := strings.TrimPrefix(fileName, "orig_")
		log.Debugf("[%s] ConvertRealName: has orig_ prefix, returning %q", internal.TagEncrypt, result)
		return result
	}

	// URL 解码文件名（与 alist-encrypt 的 decodeURIComponent 一致）
	if decoded, err := url.PathUnescape(fileName); err == nil {
		fileName = decoded
	}

	// 1. 优先查找缓存（由 ConvertShowName 建立的 显示名 → 真实加密名 映射）
	if cachedRealName, ok := GetCachedRealName(dir, fileName); ok {
		log.Debugf("[%s] ConvertRealName: cache hit, %q -> %q", internal.TagEncrypt, fileName, cachedRealName)
		return cachedRealName
	}

	// 2. 解析后缀标记（降级方案：直接URL访问时缓存未命中）
	externalSuffix := ""
	if idx := strings.Index(fileName, suffixMarker); idx != -1 {
		endIdx := strings.Index(fileName[idx:], suffixMarkerEnd)
		if endIdx != -1 {
			externalSuffix = fileName[idx+len(suffixMarker) : idx+endIdx]
			fileName = fileName[:idx] + fileName[idx+endIdx+1:]
			log.Debugf("[%s] ConvertRealName: parsed suffix marker, externalSuffix=%q, fileName=%q", internal.TagEncrypt, externalSuffix, fileName)
		}
	}

	ext := path.Ext(fileName)
	outputExt := ext
	if normalized := NormalizeEncSuffix(encSuffix); normalized != "" {
		outputExt = normalized
	}

	// 直接加密完整文件名（含扩展名），然后再加扩展名
	// 与 alist-encrypt 一致：总是加密，不检查是否已加密
	encName := EncodeName(password, encType, fileName)

	// 加密后还原外部后缀
	result := encName + externalSuffix + outputExt
	log.Debugf("[%s] ConvertRealName: fileName=%q, ext=%q, outputExt=%q, encName=%q, externalSuffix=%q, result=%q", internal.TagEncrypt, fileName, ext, outputExt, encName, externalSuffix, result)
	return result
}

// ConvertShowName 将加密名转换为显示名
func ConvertShowName(password string, encType EncryptionType, pathText string) string {
	return ConvertShowNameWithSuffix(password, encType, pathText, "")
}

// ConvertShowNameWithSuffix 将加密名转换为显示名，并支持按配置后缀分流解密
func ConvertShowNameWithSuffix(password string, encType EncryptionType, pathText, encSuffix string) string {
	dir := path.Dir(pathText)
	fileName := path.Base(pathText)
	originalFileName := fileName // 保存原始文件名用于缓存

	// URL 解码
	if decoded, err := url.PathUnescape(fileName); err == nil {
		fileName = decoded
		originalFileName = decoded
	}
	ext := path.Ext(fileName)
	encName := strings.TrimSuffix(fileName, ext)
	normalizedSuffix := NormalizeEncSuffix(encSuffix)
	useHiddenSuffixFlow := normalizedSuffix != "" && ext == normalizedSuffix

	// 尝试解码
	showName := decodeNameCached(password, encType, encName)
	if showName == "" {
		// 配置了加密后缀时，启用后缀回退（处理 xx(1).bin 等场景）
		if useHiddenSuffixFlow {
			strippedName, suffix := stripExternalSuffix(encName)
			if suffix != "" {
				showName = decodeNameCached(password, encType, strippedName)
				if showName != "" {
					log.Debugf("[%s] ConvertShowName: decoded after stripping suffix %q: %q -> %q", internal.TagDecrypt, suffix, encName, showName)
					// 缓存映射：显示名 -> 真实加密名（包含外部后缀）
					CacheNameMapping(dir, showName, originalFileName)
					// 返回带后缀标记的显示名（降级方案：直接URL访问时使用）
					// 例如：KBR-008{__esuffix__ (1)}.mp4
					baseShowName := strings.TrimSuffix(showName, path.Ext(showName))
					showExt := path.Ext(showName)
					markedName := baseShowName + suffixMarker + suffix + suffixMarkerEnd + showExt
					log.Debugf("[%s] ConvertShowName: marked showName=%q, cached %q -> %q", internal.TagDecrypt, markedName, showName, originalFileName)
					return markedName
				}
			}
		}

		// 解码失败（可能是明文文件或损坏的密文）
		// 添加 orig_ 前缀，这样 ConvertRealName 就知道这是未加密的文件名，不需要再次加密
		// 这与 alist-encrypt 的行为一致
		result := "orig_" + fileName
		log.Debugf("[%s] ConvertShowName: decode failed for %q, returning %q", internal.TagDecrypt, encName, result)
		return result
	}

	// 解码成功，缓存映射
	CacheNameMapping(dir, showName, originalFileName)

	// Node.js 逻辑中，加密的是完整文件名（含后缀），且解密后不再附加后缀
	log.Debugf("[%s] ConvertShowName: %q (ext=%q, encName=%q) -> %q", internal.TagDecrypt, pathText, ext, encName, showName)
	return showName
}

// NormalizeEncSuffix 规范化加密后缀，非空时保证以 '.' 开头
func NormalizeEncSuffix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, ".") {
		return s
	}
	return "." + s
}

// EncryptFilename 加密文件名（简单封装）
func EncryptFilename(password string, encType EncryptionType, filename string) (string, error) {
	return EncodeName(password, encType, filename), nil
}

// DecryptFilename 解密文件名（简单封装）
func DecryptFilename(password string, encType EncryptionType, encryptedName string) (string, error) {
	result := DecodeName(password, encType, encryptedName)
	if result == "" {
		return "", errors.New("failed to decrypt filename")
	}
	return result, nil
}
