package encrypt

import (
	"testing"
)

func TestCRC6_Checksum(t *testing.T) {
	crc6 := NewCRC6()

	tests := []struct {
		input    string
		expected byte
	}{
		{"123456", 14},
		{"abc", 16},
		{"hello world", 41},
		{"filename.txt", 37},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := crc6.Checksum([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("Checksum(%q) = %d; want %d", tt.input, result, tt.expected)
			}
		})
	}
}