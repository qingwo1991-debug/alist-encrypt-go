package encrypt

// CRC6 计算器
type CRC6 struct {
	table [256]byte
}

// NewCRC6 创建 CRC6 计算器
func NewCRC6() *CRC6 {
	c := &CRC6{}
	c.initTable()
	return c
}

// initTable 初始化 CRC 查找表 (兼容 Node.js 实现: 右移, poly=0x30)
func (c *CRC6) initTable() {
	poly := byte(0x30)

	for i := 0; i < 256; i++ {
		crc := byte(i)
		for j := 0; j < 8; j++ {
			if crc&0x01 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		c.table[i] = crc
	}
}

// Checksum 计算 CRC6 校验和
func (c *CRC6) Checksum(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		// Node.js: c = this.table[(c ^ byteArray[i]) % 256]
		index := crc ^ b
		crc = c.table[index]
	}
	// Node.js doesn't explicit mask at end of loop, but table calculation implies 8-bit result?
	// The table calculation: ((curr >> 1) ^ 0x30) % 256.
	// Wait, Node.js table values are 0-255? Yes.
	// "return c" - CRC6 in Node returns "8-bit checksum" (from comment in crc6-8.js),
	// but since it's CRC6, the user might expect 6 bits.
	// In Node.js code `crc6-8.js`:
	// "Returns the 8-bit checksum given an array of byte-sized numbers"
	// But `commonUtil.ts`: `const crc6Check = MixBase64.getSourceChar(crc6Bit)`
	// MixBase64 usually expects index within range.
	// Let's check `alist-encrypt/node-proxy/src/utils/mixBase64.js` to see `getSourceChar`.
	return crc
}

// CRC8 计算器
type CRC8 struct {
	table [256]byte
}

// NewCRC8 创建 CRC8 计算器
func NewCRC8() *CRC8 {
	c := &CRC8{}
	c.initTable()
	return c
}

// initTable 初始化 CRC 查找表
func (c *CRC8) initTable() {
	poly := byte(0x07) // CRC-8 多项式

	for i := 0; i < 256; i++ {
		crc := byte(i)
		for j := 0; j < 8; j++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
		c.table[i] = crc
	}
}

// Checksum 计算 CRC8 校验和
func (c *CRC8) Checksum(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		crc = c.table[crc^b]
	}
	return crc
}