package encrypt

const v2KeyPrewarmMaxEntries = 8

type v2KeyPrewarmSpec struct {
	password string
	salt     string
	keyLen   int
}

func v2KeyPrewarmSpecForPath(encPath *EncryptPath) (v2KeyPrewarmSpec, bool) {
	if encPath == nil || !encPath.Enable {
		return v2KeyPrewarmSpec{}, false
	}

	spec := v2KeyPrewarmSpec{
		password: encPath.Password,
		salt:     "AES-CTR-v2",
		keyLen:   16,
	}
	switch normalizeContentEncType(EncryptionType(encPath.EncType)) {
	case EncTypeChaCha20:
		spec.salt = "ChaCha20-v2"
		spec.keyLen = 32
	case EncTypeRC4:
		spec.salt = "RC4-v2"
	}
	return spec, true
}

func collectV2KeyPrewarmSpecs(config *ProxyConfig) []v2KeyPrewarmSpec {
	if config == nil {
		return nil
	}

	specs := make([]v2KeyPrewarmSpec, 0, min(len(config.EncryptPaths), v2KeyPrewarmMaxEntries))
	seen := make(map[string]struct{}, len(config.EncryptPaths))
	for _, encPath := range config.EncryptPaths {
		spec, ok := v2KeyPrewarmSpecForPath(encPath)
		if !ok {
			continue
		}
		cacheKey := v2KeyCacheKey(spec.password, spec.salt, spec.keyLen)
		if _, ok := seen[cacheKey]; ok {
			continue
		}
		seen[cacheKey] = struct{}{}
		specs = append(specs, spec)
		if len(specs) == v2KeyPrewarmMaxEntries {
			break
		}
	}
	return specs
}

// prewarmConfiguredV2KeysAsync moves the expensive first PBKDF2 calculation
// out of the first-frame request. The derivation remains identical to the
// normal playback path and is deduplicated by the shared key cache and
// singleflight group.
func prewarmConfiguredV2KeysAsync(config *ProxyConfig) {
	specs := collectV2KeyPrewarmSpecs(config)
	if len(specs) == 0 {
		return
	}
	go func() {
		for _, spec := range specs {
			_ = cachedV2Key(spec.password, spec.salt, spec.keyLen)
		}
	}()
}
