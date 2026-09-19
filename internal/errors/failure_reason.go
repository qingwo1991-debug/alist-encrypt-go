package errors

// FailureReason is a strongly-typed, stable identifier for why a playback
// stream (or upstream probe) did not complete. Previously these were ad-hoc
// strings sprinkled through internal/handler and internal/proxy, compared and
// produced by name; typing them makes the vocabulary a single exported,
// greppable enum and prevents typo'd values passing silently.
//
// A FailureReason doubles as a normal string: it keeps its historical JSON
// encoding ("failure_reason": "client_disconnect") so persisted records and
// observability output are unchanged.
type FailureReason string

// Known playback/probe failure reasons.
const (
	// Client/context side.
	ReasonClientDisconnect FailureReason = "client_disconnect"
	ReasonContextCanceled  FailureReason = "context_canceled"
	ReasonBrokenPipe       FailureReason = "broken_pipe"
	ReasonConnectionReset  FailureReason = "connection_reset"
	ReasonTimeout          FailureReason = "timeout"
	ReasonNetworkError     FailureReason = "network_error"

	// Upstream/HTTP side.
	ReasonUpstream4xx      FailureReason = "upstream_4xx"
	ReasonUpstream5xx      FailureReason = "upstream_5xx"
	ReasonRangeUnsupported FailureReason = "range_unsupported"
	ReasonRangeInvalid     FailureReason = "range_invalid"

	// Content/streaming side.
	ReasonChunkedSeekTooLarge FailureReason = "chunked_seek_too_large"
	ReasonStreamError         FailureReason = "stream_error"
	ReasonDecryptionFailed    FailureReason = "decryption_failed"

	// raw_url resolution.
	ReasonRawURLEmpty       FailureReason = "raw_url_empty"
	ReasonRawURLSignExpired FailureReason = "raw_url_sign_expired"
	ReasonRawURLInvalidJSON FailureReason = "raw_url_invalid_json"
	ReasonRawURLHTTPStatus  FailureReason = "raw_url_http_"
	ReasonRawURLRedirect    FailureReason = "raw_url_redirect"
	ReasonRawURLFetch       FailureReason = "raw_url_fetch:"
	// raw_url redirect sub-classifications.
	ReasonRawURLRedirectRequest  FailureReason = "raw_url_redirect_request"
	ReasonRawURLRedirectLocation FailureReason = "raw_url_redirect_location"
	ReasonRawURLRedirectInvalid  FailureReason = "raw_url_redirect_invalid"

	// Range/stream capability side.
	ReasonRangeUnsatisfiable      FailureReason = "range_unsatisfiable"
	ReasonCircuitOpen             FailureReason = "circuit_open"
	ReasonDecryptValidationFailed FailureReason = "decrypt_validation_failed"
	ReasonSizeResolve             FailureReason = "size_resolve:"
	ReasonNoWarmArtifact          FailureReason = "no_warm_artifact"

	// Fallback placeholder for anything not yet classified.
	ReasonUnknown FailureReason = "unknown"
)

// Empty reports whether no concrete reason was recorded.
func (r FailureReason) Empty() bool { return r == "" }

// String implements fmt.Stringer (identical to the raw value).
func (r FailureReason) String() string { return string(r) }
