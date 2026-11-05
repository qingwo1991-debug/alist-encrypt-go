package quota

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func yun139Storage(addition string) Storage {
	return Storage{
		ID:        1,
		MountPath: "/移动云盘156",
		Driver:    yun139Driver,
		Addition:  func(context.Context) (string, error) { return addition, nil },
	}
}

func yun139TestProvider(endpoint string) *Yun139Provider {
	p := NewYun139Provider(endpoint)
	p.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	p.random = func(int) string { return "abcdefghijklmnop" }
	return p
}

// The endpoint and the unit come from the OpenList driver, so the response shape
// here mirrors what that driver parses: data.diskSize and data.freeDiskSize in
// megabytes.
func TestYun139ProviderReportsExactBytes(t *testing.T) {
	var gotBody string
	var gotHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody, gotHeaders = string(raw), r.Header.Clone()
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		_, _ = w.Write([]byte(`{"success":true,"code":"0000","message":"请求成功","data":{"freeDiskSize":1000,"diskSize":2000}}`))
	}))
	defer server.Close()

	provider := yun139TestProvider(server.URL)
	result, err := provider.Quota(context.Background(), yun139Storage(`{"authorization":"cGM6MTU2Ong=","type":"personal_new"}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2000*yun139MB || result.Used != 1000*yun139MB || result.OverQuota {
		t.Fatalf("result=%+v", result)
	}
	if result.Scope != "personal" {
		t.Fatalf("scope=%q", result.Scope)
	}
	if gotBody != `{"userDomainId":""}` {
		t.Fatalf("body=%q", gotBody)
	}
	if got := gotHeaders.Get("Authorization"); got != "Basic cGM6MTU2Ong=" {
		t.Fatalf("authorization=%q", got)
	}
	if got := gotHeaders.Get("x-SvcType"); got != "1" {
		t.Fatalf("x-SvcType=%q", got)
	}
	parts := strings.Split(gotHeaders.Get("mcloud-sign"), ",")
	if len(parts) != 3 || parts[0] != "2026-01-01 00:00:00" || parts[1] != "abcdefghijklmnop" || parts[2] != yun139Sign(gotBody, parts[0], parts[1]) {
		t.Fatalf("mcloud-sign=%q", gotHeaders.Get("mcloud-sign"))
	}
}

// A live personal_new storage returns a negative freeDiskSize: the account is
// over quota. That is a real answer, so total and used are reported and the
// availability is flagged as unknown instead of being published as negative.
func TestYun139ProviderAcceptsOverQuotaAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"code":"0000","data":{"freeDiskSize":-1540744,"diskSize":133120}}`))
	}))
	defer server.Close()

	result, err := yun139TestProvider(server.URL).Quota(context.Background(), yun139Storage(`{"authorization":"token","type":"personal_new"}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 133120*yun139MB || result.Used != (133120+1540744)*yun139MB {
		t.Fatalf("result=%+v", result)
	}
	if !result.OverQuota {
		t.Fatalf("over quota not reported: %+v", result)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("over quota rejected: %v", err)
	}
}

func TestYun139ProviderFamilyScope(t *testing.T) {
	var svcType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svcType = r.Header.Get("x-SvcType")
		_, _ = w.Write([]byte(`{"success":true,"code":"0000","data":{"freeDiskSize":10,"diskSize":100}}`))
	}))
	defer server.Close()

	result, err := yun139TestProvider(server.URL).Quota(context.Background(), yun139Storage(`{"authorization":"token","type":"family"}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.Scope != "family" || svcType != "2" {
		t.Fatalf("scope=%q svcType=%q", result.Scope, svcType)
	}
}

// Every failure mode must surface as an error: a rejected or malformed provider
// answer must never be turned into a zero-byte quota.
func TestYun139ProviderRejectsUnusableAnswers(t *testing.T) {
	cases := map[string]struct {
		body     string
		status   int
		addition string
	}{
		"provider refused":   {body: `{"success":false,"code":"01000101","message":"服务器响应异常"}`, status: 200, addition: `{"authorization":"token"}`},
		"zero disk size":     {body: `{"success":true,"code":"0000","data":{"freeDiskSize":0,"diskSize":0}}`, status: 200, addition: `{"authorization":"token"}`},
		"negative used":      {body: `{"success":true,"code":"0000","data":{"freeDiskSize":200,"diskSize":100}}`, status: 200, addition: `{"authorization":"token"}`},
		"http error":         {body: `{}`, status: 500, addition: `{"authorization":"token"}`},
		"not json":           {body: `<html>`, status: 200, addition: `{"authorization":"token"}`},
		"missing auth":       {body: `{"success":true,"code":"0000","data":{"freeDiskSize":1,"diskSize":2}}`, status: 200, addition: `{"type":"personal_new"}`},
		"malformed addition": {body: `{"success":true,"code":"0000","data":{"freeDiskSize":1,"diskSize":2}}`, status: 200, addition: `not-json`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			if _, err := yun139TestProvider(server.URL).Quota(context.Background(), yun139Storage(tc.addition)); err == nil {
				t.Fatal("unusable answer accepted")
			}
		})
	}
}

// A nil loader or a failing loader is a caller bug, not a quota of zero.
func TestYun139ProviderRequiresAddition(t *testing.T) {
	provider := NewYun139Provider("")
	if _, err := provider.Quota(context.Background(), Storage{Driver: yun139Driver}); err == nil {
		t.Fatal("missing loader accepted")
	}
	sentinel := errors.New("boom")
	storage := Storage{Driver: yun139Driver, Addition: func(context.Context) (string, error) { return "", sentinel }}
	if _, err := provider.Quota(context.Background(), storage); !errors.Is(err, sentinel) {
		t.Fatalf("err=%v", err)
	}
}

// Vector computed from calSign in drivers/139/util.go for body
// {"userDomainId":""}, ts 2026-01-01 00:00:00 and nonce abcdefghijklmnop.
func TestYun139SignMatchesDriverAlgorithm(t *testing.T) {
	const want = "2CF67D142536A05066CD702A2E11C234"
	if got := yun139Sign(`{"userDomainId":""}`, "2026-01-01 00:00:00", "abcdefghijklmnop"); got != want {
		t.Fatalf("sign=%s want=%s", got, want)
	}
	if got := yun139EncodeURIComponent(`{"userDomainId":""}`); got != "%7B%22userDomainId%22%3A%22%22%7D" {
		t.Fatalf("encode=%s", got)
	}
}

// The live endpoint answered success for an empty user_domain_id, so the
// provider forwards the configured value instead of refusing like the driver.
func TestYun139ProviderForwardsEmptyUserDomainID(t *testing.T) {
	var body map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"success":true,"code":"0000","data":{"freeDiskSize":10,"diskSize":100}}`))
	}))
	defer server.Close()
	if _, err := yun139TestProvider(server.URL).Quota(context.Background(), yun139Storage(`{"authorization":"token","type":"personal_new","user_domain_id":""}`)); err != nil {
		t.Fatal(err)
	}
	if value, ok := body["userDomainId"]; !ok || value != "" {
		t.Fatalf("body=%v", body)
	}
}
