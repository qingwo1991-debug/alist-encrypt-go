package encrypt

import core "github.com/alist-encrypt-go/shared/encryptcore"

// Shared bounded recognition capability. This is deliberately not registered as
// a client URL/range API: mobile has no authorized video-alias recovery flow or
// verified alias store yet. A future instance owner must bind paths/auth/config,
// own Stop, and publish only after checking its current rule/config revision.
// Keeping aliases here avoids duplicating HTTP, record authentication or KDF.
type MediaRecognizer = core.MediaRecognizer
type MediaRecognitionConfig = core.MediaRecognitionConfig
type MediaRecognitionResult = core.MediaRecognitionResult

func NewMediaRecognitionCapability(config MediaRecognitionConfig) *MediaRecognizer {
	return core.NewMediaRecognizer(config)
}
