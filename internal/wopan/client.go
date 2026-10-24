// Package wopan implements the personal-account quota and recycle operations of
// the WoPan protocol used by OpenList 4.2.7 (wopan-sdk-go v0.1.5).
//
// It never refreshes tokens or stores account sessions. EmptyRecycle permanently
// empties the whole personal account's recycle bin, not just a mounted directory.
// Authorization, scope checks, and single-use confirmation belong to the caller.
package wopan

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // Required by the provider's public request-signing protocol.
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	providerOrigin = "https://panservice.mail.wo.cn"
	clientID       = "1001000021"
	// These are public protocol constants, not account credentials.
	protocolKey      = "XFmi9GS2hzk98jGX"
	protocolIV       = "wNSOYIB1k1DjY5lA"
	defaultUserAgent = "OpenList/4.2.7"
	maxResponseBytes = 256 * 1024
	maxTimeout       = 15 * time.Second
)

// Stable, deliberately nonsensitive error codes. Provider descriptions, HTTP
// bodies, transport error strings, account IDs, and tokens are never included.
const (
	CodeInvalidToken    = "invalid_provider_token"
	CodeInvalidIdentity = "invalid_provider_identity"
	CodeRequest         = "provider_request_failed"
	CodeHTTP            = "provider_http_error"
	CodeRedirect        = "provider_redirect_denied"
	CodeTooLarge        = "provider_response_too_large"
	CodeResponse        = "invalid_provider_response"
	CodeBusiness        = "provider_business_error"
	CodeCiphertext      = "invalid_encrypted_payload"
	CodeData            = "invalid_provider_data"
	CodeCapacity        = "invalid_capacity"
	CodeCanceled        = "provider_canceled"
	CodeTimeout         = "provider_timeout"
)

// Error contains only a stable code safe for logs and API responses. Only safe
// context sentinels may be unwrapped; errors.Is works for cancellation/deadlines.
type Error struct {
	Code  string
	cause error
}

func (e *Error) Error() string { return "wopan: " + e.Code }
func (e *Error) Unwrap() error { return e.cause }

func failure(code string) error { return &Error{Code: code} }

// Account identifies the personal account returned by AppQueryUser.
type Account struct {
	ID string
}

// Quota is the provider's exact byte quota. No recycle size/list is available
// through this protocol; callers must not infer a recycle size from these values.
type Quota struct {
	TotalBytes     int64
	UsedBytes      int64
	AvailableBytes int64
}

// Client has no per-account state and may be shared by concurrent callers.
type Client struct {
	http *http.Client
}

// NewClient copies the supplied client, preserves its transport, caps its timeout
// at 15 seconds, disables cookie persistence, and forbids every redirect. It does
// not modify the supplied client. A nil argument uses the standard transport.
func NewClient(client *http.Client) *Client {
	var own http.Client
	if client != nil {
		own = *client
	}
	if own.Timeout <= 0 || own.Timeout > maxTimeout {
		own.Timeout = maxTimeout
	}
	own.Jar = nil
	own.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{http: &own}
}

// Account reads the account identity without refreshing or retaining its token.
func (c *Client) Account(ctx context.Context, accessToken string) (Account, error) {
	data, err := c.request(ctx, accessToken, "api-user", "AppQueryUser", map[string]string{
		"accessToken": accessToken,
	}, true, false)
	if err != nil {
		return Account{}, err
	}
	id, ok := data["userId"].(string)
	if !ok || !validIdentity(id) {
		return Account{}, failure(CodeInvalidIdentity)
	}
	return Account{ID: id}, nil
}

// Quota reads personal quota for the identity previously returned by Account.
func (c *Client) Quota(ctx context.Context, accessToken, accountID string) (Quota, error) {
	if !validIdentity(accountID) {
		return Quota{}, failure(CodeInvalidIdentity)
	}
	data, err := c.request(ctx, accessToken, "wohome", "QueryCloudUsageInfo", map[string]string{
		"phoneNum": accountID,
		"clientId": clientID,
	}, false, false)
	if err != nil {
		return Quota{}, err
	}
	usage, ok := data["usageInfo"].(map[string]any)
	if !ok {
		return Quota{}, failure(CodeCapacity)
	}
	total, totalOK := exactInt64(usage["byteTotalSize"])
	used, usedOK := exactInt64(usage["byteUsedSize"])
	if !totalOK || !usedOK || total <= 0 || used > total {
		return Quota{}, failure(CodeCapacity)
	}
	return Quota{TotalBytes: total, UsedBytes: used, AvailableBytes: total - used}, nil
}

// EmptyRecycle permanently empties the ENTIRE personal account's recycle bin.
// It sends exactly one request, with no automatic retry or token refresh. The
// caller must enforce personal-account scope, admin authorization, and explicit
// single-use confirmation before invoking this method.
func (c *Client) EmptyRecycle(ctx context.Context, accessToken string) error {
	_, err := c.request(ctx, accessToken, "wohome", "EmptyRecycleData", map[string]string{
		"clientId": clientID,
	}, false, true)
	return err
}

func validToken(token string) bool {
	if len(token) < aes.BlockSize || len(token) > 8192 {
		return false
	}
	for i := range token {
		if token[i] < 33 || token[i] > 126 {
			return false
		}
	}
	return true
}

func validIdentity(id string) bool {
	if id == "" || len(id) > 128 || !utf8.ValidString(id) || strings.TrimSpace(id) != id {
		return false
	}
	for _, r := range id {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (c *Client) request(ctx context.Context, token, channel, method string, param map[string]string, includeClientID, optionalData bool) (map[string]any, error) {
	if ctx == nil || c == nil || c.http == nil {
		return nil, failure(CodeRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, safeIOError(ctx, err)
	}
	if !validToken(token) {
		return nil, failure(CodeInvalidToken)
	}
	key := []byte(token[:aes.BlockSize])
	if channel == "api-user" {
		key = []byte(protocolKey)
	}
	plain, err := json.Marshal(param)
	if err != nil {
		return nil, failure(CodeRequest)
	}
	encrypted, err := encrypt(plain, key)
	if err != nil {
		return nil, failure(CodeRequest)
	}
	seq, err := rand.Int(rand.Reader, big.NewInt(8999))
	if err != nil {
		return nil, failure(CodeRequest)
	}
	now, reqSeq := time.Now().UnixMilli(), seq.Int64()+100000
	sign := md5.Sum([]byte(fmt.Sprintf("%s%d%d%s", method, now, reqSeq, channel)))
	header := map[string]any{
		"key": method, "resTime": now, "reqSeq": reqSeq, "channel": channel,
		"sign": hex.EncodeToString(sign[:]), "version": "",
	}
	body := map[string]any{"secret": true, "param": encrypted}
	if includeClientID {
		body["clientId"] = clientID
	}
	payload, err := json.Marshal(map[string]any{"header": header, "body": body})
	if err != nil {
		return nil, failure(CodeRequest)
	}
	// No caller-provided URL, path, query, origin, or response URL is ever used.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, providerOrigin+"/"+channel+"/dispatcher", bytes.NewReader(payload))
	if err != nil {
		return nil, failure(CodeRequest)
	}
	req.Header.Set("Accesstoken", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Origin", "https://pan.wo.cn")
	req.Header.Set("Referer", "https://pan.wo.cn/")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, safeIOError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, failure(CodeRedirect)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, failure(CodeHTTP)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, safeIOError(ctx, err)
	}
	if len(raw) > maxResponseBytes {
		return nil, failure(CodeTooLarge)
	}
	outer, err := jsonObject(raw)
	if err != nil {
		return nil, failure(CodeResponse)
	}
	statusOK := outer["STATUS"] == "200" || outer["STATUS"] == json.Number("200")
	rsp, ok := outer["RSP"].(map[string]any)
	if !statusOK || !ok || rsp["RSP_CODE"] != "0000" {
		return nil, failure(CodeBusiness)
	}
	data, exists := rsp["DATA"]
	// The SDK passes a nil result for EmptyRecycleData, so no DATA is required.
	if optionalData && (!exists || data == nil || data == "") {
		return nil, nil
	}
	result, err := decodeData(data, key)
	if err != nil {
		return nil, err
	}
	if code, exists := result["code"]; exists && code != "0000" {
		return nil, failure(CodeBusiness)
	}
	return result, nil
}

func safeIOError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return &Error{Code: CodeCanceled, cause: context.Canceled}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: CodeTimeout, cause: context.DeadlineExceeded}
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return &Error{Code: CodeTimeout, cause: context.DeadlineExceeded}
	}
	return failure(CodeRequest)
}

func encrypt(plain, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", failure(CodeCiphertext)
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+padding)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, []byte(protocolIV)).CryptBlocks(padded, padded)
	return base64.StdEncoding.EncodeToString(padded), nil
}

func decrypt(encoded string, key []byte) ([]byte, error) {
	// DecodeString otherwise silently ignores CR/LF, which is not strict base64.
	if strings.ContainsAny(encoded, "\r\n") {
		return nil, failure(CodeCiphertext)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw)%aes.BlockSize != 0 {
		return nil, failure(CodeCiphertext)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, failure(CodeCiphertext)
	}
	cipher.NewCBCDecrypter(block, []byte(protocolIV)).CryptBlocks(raw, raw)
	padding := int(raw[len(raw)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(raw) {
		return nil, failure(CodeCiphertext)
	}
	for _, b := range raw[len(raw)-padding:] {
		if int(b) != padding {
			return nil, failure(CodeCiphertext)
		}
	}
	return raw[:len(raw)-padding], nil
}

func decodeData(data any, key []byte) (map[string]any, error) {
	if object, ok := data.(map[string]any); ok {
		return object, nil
	}
	text, ok := data.(string)
	if !ok {
		return nil, failure(CodeData)
	}
	raw := []byte(text)
	if !strings.HasPrefix(strings.TrimSpace(text), "{") {
		var err error
		raw, err = decrypt(text, key)
		if err != nil {
			return nil, err
		}
	}
	object, err := jsonObject(raw)
	if err != nil {
		return nil, failure(CodeData)
	}
	return object, nil
}

func exactInt64(value any) (int64, bool) {
	var text string
	switch value := value.(type) {
	case string:
		text = value
	case json.Number:
		text = string(value)
	default:
		return 0, false
	}
	if text == "" {
		return 0, false
	}
	for i := range text {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(text, 10, 64)
	return n, err == nil
}

// jsonObject rejects duplicate keys at every level, trailing JSON, invalid UTF-8,
// and excessive nesting. UseNumber prevents lossy float64 quota conversions.
func jsonObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, failure(CodeResponse)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := jsonValue(decoder, 0)
	if err != nil {
		return nil, failure(CodeResponse)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, failure(CodeResponse)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, failure(CodeResponse)
	}
	return object, nil
}

func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, failure(CodeResponse)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := name.(string)
			if !ok {
				return nil, failure(CodeResponse)
			}
			if _, exists := object[key]; exists {
				return nil, failure(CodeResponse)
			}
			value, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, failure(CodeResponse)
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, failure(CodeResponse)
		}
		return array, nil
	default:
		return nil, failure(CodeResponse)
	}
}
