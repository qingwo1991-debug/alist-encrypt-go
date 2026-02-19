package mysqlstore

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"time"
)

const tablePrefix = "alist_encrypt_"

func TableName(base string) string {
	return tablePrefix + base
}

func KeyHash(providerHost, originalPath string) string {
	sum := md5.Sum([]byte(providerHost + "::" + originalPath))
	return hex.EncodeToString(sum[:])
}

func SplitProviderKey(providerKey string) (string, string) {
	parts := strings.SplitN(providerKey, "::", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return providerKey, ""
}

type StrategyRecord struct {
	KeyHash        string
	ProviderHost   string
	OriginalPath   string
	Preferred      string
	FailuresJSON   string
	SuccessStreak  int
	TotalFailures  int
	TotalSuccesses int
	CooldownUntil  time.Time
	LastDowngrade  time.Time
	LastFailure    string
	LastStrategy   string
	UpdatedAt      time.Time
	LastAccessed   time.Time
}

type FileMetaRecord struct {
	KeyHash      string
	ProviderHost string
	OriginalPath string
	Size         int64
	ETag         string
	ContentType  string
	UpdatedAt    time.Time
	LastAccessed time.Time
	StatusCode   int
	Active       bool
}

type RangeCompatRecord struct {
	KeyHash              string
	ProviderHost         string
	StorageKey           string
	Incompatible         bool
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	NextProbeAt          time.Time
	LastReason           string
	LastCheckedAt        time.Time
	UpdatedAt            time.Time
	LastAccessed         time.Time
	Active               bool
}
