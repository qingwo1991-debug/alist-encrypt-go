package encrypt

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
)

// SegmentPosition 重置 S-box 的位置间隔 (1MB)
const SegmentPosition = 100 * 10000

// RC4StateCache 缓存 RC4 状态，用于加速 SetPosition
type RC4StateCache struct {
	sbox     [256]int
	i, j     int
	position int64
}

// CustomRC4 实现兼容 Node.js 版本的 RC4 算法
type CustomRC4 struct {
	password      string
	sizeSalt      string
	passwdOutward string
	fileHexKey    string // string of hex

	sbox [256]int
	i    int
	j    int
	position int64

	// 状态缓存：每 256KB 保存一次状态，加速随机访问
	stateCache    map[int64]*RC4StateCache
	cacheInterval int64
}

// NewCustomRC4 创建 CustomRC4 实例
func NewCustomRC4(password, sizeSalt, passwdOutward string) *CustomRC4 {
	// fileHexKey: md5(passwdOutward + sizeSalt)
	passwdSalt := passwdOutward + sizeSalt
	hash := md5.Sum([]byte(passwdSalt))
	fileHexKey := hex.EncodeToString(hash[:])

	rc4 := &CustomRC4{
		password:      password,
		sizeSalt:      sizeSalt,
		passwdOutward: passwdOutward,
		fileHexKey:    fileHexKey,
		position:      0,
		stateCache:    make(map[int64]*RC4StateCache),
		cacheInterval: 256 * 1024, // 每 256KB 缓存一次状态
	}
	rc4.resetKSA()
	return rc4
}

// initKSA 初始化 KSA
func (c *CustomRC4) initKSA(key []byte) {
	// Init sbox
	for i := 0; i < 256; i++ {
		c.sbox[i] = i
	}

	kLen := len(key)
	K := make([]int, 256)
	for i := 0; i < 256; i++ {
		K[i] = int(key[i%kLen])
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + c.sbox[i] + K[i]) % 256
		c.sbox[i], c.sbox[j] = c.sbox[j], c.sbox[i]
	}

	c.i = 0
	c.j = 0
}

// resetKSA 重置 S-box
func (c *CustomRC4) resetKSA() {
	offset := int(c.position / SegmentPosition) * SegmentPosition
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(offset))

	// rc4Key = Buffer.from(fileHexKey, 'hex')
	rc4Key, _ := hex.DecodeString(c.fileHexKey)

	// XOR last bytes with offset
	j := len(rc4Key) - len(buf)
	for i := 0; i < len(buf); i++ {
		rc4Key[j] ^= buf[i]
		j++
	}

	c.initKSA(rc4Key)
}

// saveState 保存当前状态到缓存
func (c *CustomRC4) saveState() {
	cacheKey := (c.position / c.cacheInterval) * c.cacheInterval
	if _, exists := c.stateCache[cacheKey]; !exists && len(c.stateCache) < 100 {
		state := &RC4StateCache{
			i:        c.i,
			j:        c.j,
			position: c.position,
		}
		copy(state.sbox[:], c.sbox[:])
		c.stateCache[cacheKey] = state
	}
}

// restoreState 从缓存恢复状态
func (c *CustomRC4) restoreState(state *RC4StateCache) {
	copy(c.sbox[:], state.sbox[:])
	c.i = state.i
	c.j = state.j
	c.position = state.position
}

// XORKeyStream 加密/解密数据
func (c *CustomRC4) XORKeyStream(dst, src []byte) {
	for k := 0; k < len(src); k++ {
		c.i = (c.i + 1) % 256
		c.j = (c.j + c.sbox[c.i]) % 256
		c.sbox[c.i], c.sbox[c.j] = c.sbox[c.j], c.sbox[c.i]

		val := src[k] ^ byte(c.sbox[(c.sbox[c.i]+c.sbox[c.j])%256])
		dst[k] = val

		c.position++
		if c.position%SegmentPosition == 0 {
			c.resetKSA()
		}

		// 定期保存状态到缓存
		if c.position%c.cacheInterval == 0 {
			c.saveState()
		}
	}
}

// SetPosition 设置位置（优化版：使用状态缓存加速）
func (c *CustomRC4) SetPosition(pos int64) {
	// 查找最近的缓存状态
	segmentStart := (pos / SegmentPosition) * SegmentPosition

	// 首先检查是否有同一 segment 内的缓存
	var bestCache *RC4StateCache
	var bestPos int64 = -1

	for cachePos, state := range c.stateCache {
		// 只使用同一 segment 内且在目标位置之前的缓存
		stateSegment := (cachePos / SegmentPosition) * SegmentPosition
		if stateSegment == segmentStart && cachePos <= pos && cachePos > bestPos {
			bestPos = cachePos
			bestCache = state
		}
	}

	if bestCache != nil && pos-bestPos < pos%SegmentPosition {
		// 从缓存恢复，然后空跑到目标位置
		c.restoreState(bestCache)
		c.prgaExecPosition(int(pos - bestPos))
		c.position = pos
	} else {
		// 没有可用缓存，使用原始方法
		c.position = pos
		c.resetKSA()
		c.prgaExecPosition(int(pos % SegmentPosition))
	}
}

// prgaExecPosition 空跑 PRGA 到指定偏移
func (c *CustomRC4) prgaExecPosition(plainLen int) {
	for k := 0; k < plainLen; k++ {
		c.i = (c.i + 1) % 256
		c.j = (c.j + c.sbox[c.i]) % 256
		c.sbox[c.i], c.sbox[c.j] = c.sbox[c.j], c.sbox[c.i]
	}
}