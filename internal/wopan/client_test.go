package wopan

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// All tests, especially EmptyRecycle tests, use fake RoundTrippers only. No test
// opens a socket or invokes the provider, and tokens/identities are fabricated.
const testToken = "0123456789abcdef-fabricated-test-token"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeClient(f roundTripFunc) *Client {
	return NewClient(&http.Client{Transport: f})
}

func response(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func success(data any) string {
	raw, err := json.Marshal(map[string]any{"STATUS": "200", "RSP": map[string]any{"RSP_CODE": "0000", "DATA": data}})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != want {
		t.Fatalf("got error %v, want code %s", err, want)
	}
	if err.Error() != "wopan: "+want {
		t.Fatalf("unsafe error text: %q", err.Error())
	}
}

// These independent protocol helpers use literal public key/IV values instead
// of the production encrypt/decrypt helpers, preventing a shared-key/IV mistake
// from making both implementation and assertions pass.
func protocolEncrypt(t *testing.T, plain string, key string) string {
	t.Helper()
	padding := 16 - len(plain)%16
	raw := append([]byte(plain), []byte(strings.Repeat(string(byte(padding)), padding))...)
	return encryptBlocks(t, raw, key)
}

func encryptBlocks(t *testing.T, padded []byte, key string) string {
	t.Helper()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), padded...)
	cipher.NewCBCEncrypter(block, []byte("wNSOYIB1k1DjY5lA")).CryptBlocks(raw, raw)
	return base64.StdEncoding.EncodeToString(raw)
}

func protocolDecrypt(t *testing.T, encoded, key string) string {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw)%16 != 0 {
		t.Fatalf("invalid request ciphertext: %v", err)
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCDecrypter(block, []byte("wNSOYIB1k1DjY5lA")).CryptBlocks(raw, raw)
	padding := int(raw[len(raw)-1])
	if padding == 0 || padding > 16 {
		t.Fatal("invalid request padding")
	}
	for _, b := range raw[len(raw)-padding:] {
		if int(b) != padding {
			t.Fatal("invalid request padding bytes")
		}
	}
	return string(raw[:len(raw)-padding])
}

func assertRequest(t *testing.T, req *http.Request, method, channel, token, wantPlain string, account bool) {
	t.Helper()
	if req.Method != http.MethodPost || req.URL.String() != "https://panservice.mail.wo.cn/"+channel+"/dispatcher" || req.Host != "panservice.mail.wo.cn" {
		t.Fatalf("unexpected endpoint: %s %s", req.Method, req.URL)
	}
	wantHeaders := map[string]string{
		"Accesstoken": token, "Content-Type": "application/json", "User-Agent": "OpenList/4.2.7",
		"Origin": "https://pan.wo.cn", "Referer": "https://pan.wo.cn/",
	}
	if len(req.Header) != len(wantHeaders) {
		t.Fatalf("unexpected headers: %v", req.Header)
	}
	for name, want := range wantHeaders {
		if req.Header.Get(name) != want {
			t.Errorf("unexpected %s header", name)
		}
	}
	var envelope struct {
		Header map[string]json.RawMessage `json:"header"`
		Body   map[string]json.RawMessage `json:"body"`
	}
	if err := json.NewDecoder(req.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Header) != 6 {
		t.Fatalf("unexpected header fields: %v", envelope.Header)
	}
	for key, want := range map[string]string{"key": method, "channel": channel, "version": ""} {
		var value string
		if err := json.Unmarshal(envelope.Header[key], &value); err != nil || value != want {
			t.Fatalf("incorrect protocol header %s", key)
		}
	}
	var timestamp, seq int64
	if err := json.Unmarshal(envelope.Header["resTime"], &timestamp); err != nil || time.Since(time.UnixMilli(timestamp)).Abs() > time.Minute {
		t.Fatal("invalid request time")
	}
	if err := json.Unmarshal(envelope.Header["reqSeq"], &seq); err != nil || seq < 100000 || seq > 108998 {
		t.Fatal("invalid request sequence")
	}
	var sign string
	if err := json.Unmarshal(envelope.Header["sign"], &sign); err != nil {
		t.Fatal(err)
	}
	digest := md5.Sum([]byte(fmt.Sprintf("%s%d%d%s", method, timestamp, seq, channel)))
	if sign != hex.EncodeToString(digest[:]) {
		t.Fatal("invalid provider signature")
	}
	wantBodyFields := 2
	if account {
		wantBodyFields++
		if string(envelope.Body["clientId"]) != `"1001000021"` {
			t.Fatal("missing account body clientId")
		}
	}
	if len(envelope.Body) != wantBodyFields || string(envelope.Body["secret"]) != "true" {
		t.Fatalf("unexpected body fields: %v", envelope.Body)
	}
	var encrypted string
	if err := json.Unmarshal(envelope.Body["param"], &encrypted); err != nil {
		t.Fatal(err)
	}
	key := token[:16]
	if channel == "api-user" {
		key = "XFmi9GS2hzk98jGX"
	}
	if got := protocolDecrypt(t, encrypted, key); got != wantPlain {
		t.Fatalf("decrypted param = %s, want %s", got, wantPlain)
	}
	if encrypted != protocolEncrypt(t, wantPlain, key) {
		t.Fatal("ciphertext not exactly the SDK protocol")
	}
}

func TestAccountExactProtocolAndResponseEncodings(t *testing.T) {
	for _, encoding := range []string{"object", "json-string", "encrypted"} {
		t.Run(encoding, func(t *testing.T) {
			plain := `{"userId":"test-account-123","code":"0000"}`
			var data any = map[string]any{"userId": "test-account-123", "code": "0000"}
			if encoding == "json-string" {
				data = plain
			} else if encoding == "encrypted" {
				data = protocolEncrypt(t, plain, "XFmi9GS2hzk98jGX")
			}
			calls := 0
			client := fakeClient(func(req *http.Request) (*http.Response, error) {
				calls++
				assertRequest(t, req, "AppQueryUser", "api-user", testToken, `{"accessToken":"`+testToken+`"}`, true)
				return response(success(data)), nil
			})
			got, err := client.Account(context.Background(), testToken)
			if err != nil || got.ID != "test-account-123" || calls != 1 {
				t.Fatalf("Account = %+v, err = %v, calls = %d", got, err, calls)
			}
		})
	}
}

func TestQuotaExactProtocolAndExactIntegers(t *testing.T) {
	for _, status := range []string{`"200"`, `200`} {
		t.Run(status, func(t *testing.T) {
			plain := `{"code":"0000","usageInfo":{"byteTotalSize":"9223372036854775807","byteUsedSize":9007199254740993}}`
			client := fakeClient(func(req *http.Request) (*http.Response, error) {
				assertRequest(t, req, "QueryCloudUsageInfo", "wohome", testToken, `{"clientId":"1001000021","phoneNum":"test-account-123"}`, false)
				body := `{"STATUS":` + status + `,"RSP":{"RSP_CODE":"0000","DATA":"` + protocolEncrypt(t, plain, testToken[:16]) + `"}}`
				return response(body), nil
			})
			got, err := client.Quota(context.Background(), testToken, "test-account-123")
			want := Quota{TotalBytes: 9223372036854775807, UsedBytes: 9007199254740993, AvailableBytes: 9214364837600034814}
			if err != nil || got != want {
				t.Fatalf("Quota = %+v, want %+v, err = %v", got, want, err)
			}
		})
	}
}

func TestQuotaRejectsInvalidCapacity(t *testing.T) {
	for _, tc := range []struct{ name, total, used string }{
		{"total overflow string", `"9223372036854775808"`, `0`},
		{"total overflow number", `9223372036854775808`, `0`},
		{"used overflow", `"9223372036854775807"`, `"9223372036854775808"`},
		{"negative total", `-1`, `0`}, {"negative used", `100`, `-1`},
		{"negative zero", `100`, `-0`}, {"negative string", `100`, `"-1"`},
		{"fractional", `100`, `1.5`}, {"float integer", `100`, `1.0`},
		{"exponent", `100`, `1e1`}, {"exponent string", `100`, `"1e1"`},
		{"zero total", `0`, `0`}, {"used over total", `100`, `101`},
		{"leading whitespace", `" 100"`, `0`}, {"plus", `"+100"`, `0`},
		{"empty", `""`, `0`}, {"null", `100`, `null`}, {"boolean", `100`, `true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fakeClient(func(*http.Request) (*http.Response, error) {
				return response(`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":{"usageInfo":{"byteTotalSize":` + tc.total + `,"byteUsedSize":` + tc.used + `}}}}`), nil
			})
			got, err := client.Quota(context.Background(), testToken, "test-account")
			assertCode(t, err, CodeCapacity)
			if got != (Quota{}) {
				t.Fatal("error returned nonzero quota")
			}
		})
	}
	for _, data := range []any{map[string]any{}, map[string]any{"usageInfo": nil}, map[string]any{"usageInfo": []any{}}, map[string]any{"usageInfo": map[string]any{"byteTotalSize": "100"}}} {
		client := fakeClient(func(*http.Request) (*http.Response, error) { return response(success(data)), nil })
		_, err := client.Quota(context.Background(), testToken, "test-account")
		assertCode(t, err, CodeCapacity)
	}
}

func TestQuotaAcceptsStringAndNumberBytes(t *testing.T) {
	for _, tc := range []struct{ total, used string }{{`"100"`, `"0"`}, {`100`, `100`}, {`"100"`, `1`}} {
		client := fakeClient(func(*http.Request) (*http.Response, error) {
			return response(`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":{"usageInfo":{"byteTotalSize":` + tc.total + `,"byteUsedSize":` + tc.used + `}}}}`), nil
		})
		got, err := client.Quota(context.Background(), testToken, "test-account")
		if err != nil || got.TotalBytes != 100 || got.AvailableBytes != got.TotalBytes-got.UsedBytes {
			t.Fatalf("invalid quota: %+v, %v", got, err)
		}
	}
}

func TestEmptyRecycleMockOnlyExactProtocol(t *testing.T) {
	for _, body := range []string{
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000"}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":null}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":""}}`,
		success(map[string]any{"code": "0000"}),
		success(protocolEncrypt(t, `{"code":"0000"}`, testToken[:16])),
	} {
		calls := 0
		client := fakeClient(func(req *http.Request) (*http.Response, error) {
			calls++
			assertRequest(t, req, "EmptyRecycleData", "wohome", testToken, `{"clientId":"1001000021"}`, false)
			return response(body), nil
		})
		if err := client.EmptyRecycle(context.Background(), testToken); err != nil || calls != 1 {
			t.Fatalf("EmptyRecycle err = %v, calls = %d", err, calls)
		}
	}
}

func TestBusinessErrorsAreSanitizedAndNeverRetried(t *testing.T) {
	for _, body := range []string{
		`{"STATUS":"500","MSG":"sensitive-provider-message","RSP":{"RSP_CODE":"0000","DATA":{}}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"9999","RSP_DESC":"sensitive-provider-message"}}`,
		success(map[string]any{"code": "9999", "message": "sensitive-provider-message"}),
		success(map[string]any{"code": 0}),
		success(map[string]any{"code": nil}),
		success(protocolEncrypt(t, `{"code":"9999","message":"sensitive-provider-message"}`, testToken[:16])),
	} {
		calls := 0
		client := fakeClient(func(*http.Request) (*http.Response, error) {
			calls++
			return response(body), nil
		})
		assertCode(t, client.EmptyRecycle(context.Background(), testToken), CodeBusiness)
		if calls != 1 {
			t.Fatalf("mutating request was retried %d times", calls)
		}
	}
	client := fakeClient(func(*http.Request) (*http.Response, error) {
		return response(success(protocolEncrypt(t, `{"code":"0001","userId":"test-account"}`, "XFmi9GS2hzk98jGX"))), nil
	})
	_, err := client.Account(context.Background(), testToken)
	assertCode(t, err, CodeBusiness)
	client = fakeClient(func(*http.Request) (*http.Response, error) {
		return response(success(map[string]any{"code": "0001", "usageInfo": map[string]any{"byteTotalSize": 100, "byteUsedSize": 0}})), nil
	})
	_, err = client.Quota(context.Background(), testToken, "test-account")
	assertCode(t, err, CodeBusiness)
}

func TestMalformedResponsesAndDuplicateKeys(t *testing.T) {
	for _, body := range []string{
		``, `null`, `[]`, `{`, `{"STATUS":"200"} {}`,
		`{"STATUS":"200","STATUS":"200","RSP":{"RSP_CODE":"0000"}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","RSP_CODE":"0000"}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":{"userId":"one","userId":"two"}}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":{"code":"0000","\u0063ode":"9999"}}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":{"ignored":[{"a":1,"a":2}]}}}`,
		`{"STATUS":"200","RSP":{"RSP_CODE":"0000","DATA":{` + strings.Repeat(`"a":[`, 70) + `0` + strings.Repeat(`]}`, 70) + `}}}`,
		"{\"invalid\":\"\xff\"}",
	} {
		client := fakeClient(func(*http.Request) (*http.Response, error) { return response(body), nil })
		_, err := client.Account(context.Background(), testToken)
		assertCode(t, err, CodeResponse)
	}
	for _, data := range []any{
		nil, false, []any{}, 100, `{"userId":"a","userId":"b"}`,
		protocolEncrypt(t, `{"userId":"a","userId":"b"}`, "XFmi9GS2hzk98jGX"),
		protocolEncrypt(t, `null`, "XFmi9GS2hzk98jGX"),
		protocolEncrypt(t, `{"userId":"a"} trailing`, "XFmi9GS2hzk98jGX"),
	} {
		client := fakeClient(func(*http.Request) (*http.Response, error) { return response(success(data)), nil })
		_, err := client.Account(context.Background(), testToken)
		assertCode(t, err, CodeData)
	}
}

func TestMalformedCiphertextAndStrictPadding(t *testing.T) {
	invalidPadding := []string{
		strings.Repeat("x", 15) + "\x00",
		strings.Repeat("x", 15) + "\x11",
		strings.Repeat("x", 14) + "\x01\x02",
	}
	encoded := []string{"not-base64!", "", "AB==", base64.StdEncoding.EncodeToString([]byte("short")), base64.StdEncoding.EncodeToString(make([]byte, 17))}
	for _, plain := range invalidPadding {
		encoded = append(encoded, encryptBlocks(t, []byte(plain), "XFmi9GS2hzk98jGX"))
	}
	valid := protocolEncrypt(t, `{"userId":"test-account"}`, "XFmi9GS2hzk98jGX")
	encoded = append(encoded, valid[:8]+"\n"+valid[8:])
	for i, ciphertext := range encoded {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			client := fakeClient(func(*http.Request) (*http.Response, error) { return response(success(ciphertext)), nil })
			_, err := client.Account(context.Background(), testToken)
			assertCode(t, err, CodeCiphertext)
		})
	}
	for length := 0; length <= 2*aes.BlockSize; length++ {
		plain := strings.Repeat("x", length)
		encoded := protocolEncrypt(t, plain, "XFmi9GS2hzk98jGX")
		got, err := decrypt(encoded, []byte("XFmi9GS2hzk98jGX"))
		if err != nil || string(got) != plain {
			t.Fatalf("valid padding rejected at length %d: %v", length, err)
		}
	}
}

func TestResponseLimitAndBodyClose(t *testing.T) {
	for _, size := range []int{maxResponseBytes, maxResponseBytes + 1} {
		closed := false
		client := fakeClient(func(*http.Request) (*http.Response, error) {
			r := response(strings.Repeat(" ", size))
			r.Body = &trackedBody{Reader: r.Body, closed: &closed}
			return r, nil
		})
		_, err := client.Account(context.Background(), testToken)
		want := CodeResponse
		if size > maxResponseBytes {
			want = CodeTooLarge
		}
		assertCode(t, err, want)
		if !closed {
			t.Fatal("response body was not closed")
		}
	}
}

type trackedBody struct {
	io.Reader
	closed *bool
}

func (b *trackedBody) Close() error { *b.closed = true; return nil }

func TestRedirectNeverForwardsCredentials(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, target := range []string{"https://attacker.invalid/token", "https://panservice.mail.wo.cn/other"} {
			calls := 0
			client := fakeClient(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 || req.URL.Host != "panservice.mail.wo.cn" || req.URL.Path != "/wohome/dispatcher" {
					t.Fatal("redirect forwarded credentials")
				}
				r := response("sensitive-redirect-body")
				r.StatusCode = status
				r.Header.Set("Location", target)
				return r, nil
			})
			assertCode(t, client.EmptyRecycle(context.Background(), testToken), CodeRedirect)
			if calls != 1 {
				t.Fatalf("redirect attempted %d calls", calls)
			}
		}
	}
}

func TestNewClientClonesAndBoundsSettings(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var callbacks atomic.Int32
	redirect := func(*http.Request, []*http.Request) error { callbacks.Add(1); return nil }
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) { return response(""), nil })
	for _, timeout := range []time.Duration{0, -time.Second, time.Second, 15 * time.Second, time.Minute} {
		original := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: redirect, Jar: jar}
		client := NewClient(original)
		wantTimeout := timeout
		if wantTimeout <= 0 || wantTimeout > 15*time.Second {
			wantTimeout = 15 * time.Second
		}
		if client.http == original || client.http.Timeout != wantTimeout || client.http.Jar != nil || reflect.ValueOf(client.http.Transport).Pointer() != reflect.ValueOf(transport).Pointer() {
			t.Fatal("client settings were not safely cloned")
		}
		if original.Timeout != timeout || original.Jar != jar || reflect.ValueOf(original.CheckRedirect).Pointer() != reflect.ValueOf(redirect).Pointer() {
			t.Fatal("original client was modified")
		}
		if err := client.http.CheckRedirect(nil, nil); err != http.ErrUseLastResponse || callbacks.Load() != 0 {
			t.Fatal("redirect policy not replaced")
		}
	}
	if NewClient(nil).http.Timeout != 15*time.Second {
		t.Fatal("nil client has unsafe timeout")
	}
}

func TestCancellationAndDeadlineAreSafe(t *testing.T) {
	for _, cancelFirst := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		if cancelFirst {
			cancel()
		}
		client := fakeClient(func(req *http.Request) (*http.Response, error) {
			calls++
			cancel()
			<-req.Context().Done()
			return nil, fmt.Errorf("sensitive-transport-%s: %w", testToken, req.Context().Err())
		})
		_, err := client.Account(ctx, testToken)
		cancel()
		assertCode(t, err, CodeCanceled)
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation sentinel not preserved")
		}
		if cancelFirst && calls != 0 {
			t.Fatal("canceled request reached transport")
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	client := fakeClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("expired request reached transport")
		return nil, nil
	})
	_, err := client.Account(ctx, testToken)
	assertCode(t, err, CodeTimeout)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline sentinel not preserved")
	}
	client = fakeClient(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("sensitive-%s: %w", testToken, context.DeadlineExceeded)
	})
	_, err = client.Account(context.Background(), testToken)
	assertCode(t, err, CodeTimeout)
}

func TestErrorsNeverExposeBodiesOrTransportDetails(t *testing.T) {
	client := fakeClient(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("sensitive transport token=%s account=test-account", testToken)
	})
	_, err := client.Account(context.Background(), testToken)
	assertCode(t, err, CodeRequest)
	if errors.Unwrap(err) != nil {
		t.Fatal("raw transport error retained")
	}
	for _, status := range []int{400, 401, 403, 500, 503} {
		client = fakeClient(func(*http.Request) (*http.Response, error) {
			r := response("sensitive raw response " + testToken)
			r.StatusCode = status
			return r, nil
		})
		_, err = client.Account(context.Background(), testToken)
		assertCode(t, err, CodeHTTP)
	}
	client = fakeClient(func(*http.Request) (*http.Response, error) {
		r := response("")
		r.Body = errorBody{}
		return r, nil
	})
	_, err = client.Account(context.Background(), testToken)
	assertCode(t, err, CodeRequest)
}

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, errors.New("sensitive read " + testToken) }
func (errorBody) Close() error             { return nil }

func TestInvalidInputsNeverReachTransport(t *testing.T) {
	client := fakeClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached provider")
		return nil, nil
	})
	for _, token := range []string{"", "short", "0123456789abcde\n", "0123456789abcde\r", "0123456789abcde ", "0123456789abcde\x00", "0123456789abcdeé", strings.Repeat("x", 8193)} {
		_, err := client.Account(context.Background(), token)
		assertCode(t, err, CodeInvalidToken)
		_, err = client.Quota(context.Background(), token, "test-account")
		assertCode(t, err, CodeInvalidToken)
		assertCode(t, client.EmptyRecycle(context.Background(), token), CodeInvalidToken)
	}
	for _, id := range []string{"", strings.Repeat("x", 129), "bad\naccount", "bad\raccount", "bad\x00account", " bad", "bad ", "\xff"} {
		_, err := client.Quota(context.Background(), testToken, id)
		assertCode(t, err, CodeInvalidIdentity)
	}
	_, err := client.Account(nil, testToken)
	assertCode(t, err, CodeRequest)
	var zero Client
	_, err = zero.Account(context.Background(), testToken)
	assertCode(t, err, CodeRequest)
}

func TestAccountRejectsInvalidIdentity(t *testing.T) {
	for _, id := range []any{nil, 123, "", strings.Repeat("x", 129), "bad\r\naccount", "bad\x00account", " account", "account "} {
		client := fakeClient(func(*http.Request) (*http.Response, error) {
			return response(success(map[string]any{"userId": id})), nil
		})
		_, err := client.Account(context.Background(), testToken)
		assertCode(t, err, CodeInvalidIdentity)
	}
}

func TestConcurrentAccountsHaveNoSharedTokenState(t *testing.T) {
	client := fakeClient(func(req *http.Request) (*http.Response, error) {
		token := req.Header.Get("Accesstoken")
		if !strings.HasPrefix(token, "fabricated-token-") {
			t.Error("unexpected account token")
		}
		var envelope struct {
			Body struct {
				Param string `json:"param"`
			} `json:"body"`
		}
		if err := json.NewDecoder(req.Body).Decode(&envelope); err != nil {
			t.Error(err)
		}
		if got := protocolDecrypt(t, envelope.Body.Param, "XFmi9GS2hzk98jGX"); got != `{"accessToken":"`+token+`"}` {
			t.Error("account token crossed requests")
		}
		return response(success(map[string]any{"userId": "account-" + strings.TrimPrefix(token, "fabricated-token-")})), nil
	})
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			got, err := client.Account(context.Background(), "fabricated-token-"+strconv.Itoa(i))
			if err != nil || got.ID != "account-"+strconv.Itoa(i) {
				t.Errorf("concurrent account mismatch: %+v, %v", got, err)
			}
		}(i)
	}
	group.Wait()
}
