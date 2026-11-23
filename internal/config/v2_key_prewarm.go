package config

import (
	"sync"

	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// v2KeyPrewarmMu serializes background prewarm passes so config saves in quick
// succession do not run several 600k-iteration PBKDF2 passes in parallel.
var v2KeyPrewarmMu sync.Mutex

// prewarmV2Keys derives the V2 base keys for every enabled encryption rule in
// the background. V2 keys are cached (see SetV2KeyCacheTTL); without this the
// first V2 playback after startup or a password change pays the full PBKDF2
// cost before its first byte. Duplicate password/encType pairs hit the cache.
func prewarmV2Keys(list []PasswdInfo) {
	rules := make([]PasswdInfo, 0, len(list))
	for _, p := range list {
		if p.Enable && len(p.Password) > 0 {
			rules = append(rules, PasswdInfo{Password: p.Password, EncType: p.EncType})
		}
	}
	if len(rules) == 0 {
		return
	}
	go func() {
		v2KeyPrewarmMu.Lock()
		defer v2KeyPrewarmMu.Unlock()
		for _, p := range rules {
			encryption.PrewarmV2Key(p.Password, p.EncType)
		}
	}()
}
