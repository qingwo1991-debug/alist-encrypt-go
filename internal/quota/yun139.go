package quota

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DefaultYun139Endpoint is the China Mobile Cloud (139) quota endpoint.
//
// Source: OpenListTeam/OpenList drivers/139/util.go getDiskQuotaDetail posts
// {"userDomainId": ...} to this URL, and drivers/139/driver.go GetDetails turns
// data.diskSize and data.freeDiskSize into total and used space:
//
//	https://github.com/OpenListTeam/OpenList/blob/main/drivers/139/util.go
//	https://github.com/OpenListTeam/OpenList/blob/main/drivers/139/driver.go
//
// The same two URLs were confirmed present in the deployed OpenList binary, so
// this endpoint is what the instance in front of these storages already calls.
const DefaultYun139Endpoint = "https://user-njs.yun.139.com/user/disk/quota/detail"

// yun139MB is the unit of diskSize and freeDiskSize. GetDetails multiplies both
// by utils.MB before reporting bytes.
const yun139MB = 1024 * 1024

// yun139Driver is the OpenList driver name this provider owns.
const yun139Driver = "139Yun"

// Yun139Provider reads exact quota from China Mobile Cloud (139). It is
// deliberately self-contained: it speaks only the provider API and knows
// nothing about HTTP handlers, storage enumeration or the WoPan client.
type Yun139Provider struct {
	endpoint string
	client   *http.Client
	now      func() time.Time
	random   func(n int) string
}

// NewYun139Provider builds the provider. An empty endpoint selects the
// production URL; tests pass their own server.
func NewYun139Provider(endpoint string) *Yun139Provider {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultYun139Endpoint
	}
	return &Yun139Provider{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 15 * time.Second},
		now:      time.Now,
		random:   yun139RandomString,
	}
}

func (p *Yun139Provider) Supports(driver string) bool { return driver == yun139Driver }

// yun139Addition is the part of a 139 storage addition this provider needs.
// Authorization is the base64 "pc:user:token" credential the driver stores;
// Type selects the personal or family API surface.
type yun139Addition struct {
	Authorization string `json:"authorization"`
	Type          string `json:"type"`
	UserDomainID  string `json:"user_domain_id"`
}

// yun139QuotaResponse mirrors DiskQuotaDetail in drivers/139/types.go. Both
// sizes are in megabytes.
type yun139QuotaResponse struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Data    struct {
		FreeDiskSize int64 `json:"freeDiskSize"`
		DiskSize     int64 `json:"diskSize"`
	} `json:"data"`
}

// Quota asks 139 for the account's disk quota.
//
// The driver refuses this call when user_domain_id is empty, but the endpoint
// itself answers for a personal account with an empty id: verified against a
// live personal_new storage, which returned success with diskSize and a
// negative freeDiskSize (the account is over quota). The configured value is
// therefore forwarded as-is instead of being rejected.
func (p *Yun139Provider) Quota(ctx context.Context, s Storage) (Result, error) {
	if p == nil || p.client == nil || s.Addition == nil {
		return Result{}, Invalid()
	}
	raw, err := s.Addition(ctx)
	if err != nil {
		return Result{}, err
	}
	var addition yun139Addition
	if err := json.Unmarshal([]byte(raw), &addition); err != nil {
		return Result{}, Invalid()
	}
	if strings.TrimSpace(addition.Authorization) == "" {
		return Result{}, Invalid()
	}
	family := strings.HasPrefix(strings.ToLower(strings.TrimSpace(addition.Type)), "family")
	body, err := json.Marshal(map[string]string{"userDomainId": addition.UserDomainID})
	if err != nil {
		return Result{}, Invalid()
	}
	resp, err := p.post(ctx, addition.Authorization, family, body)
	if err != nil {
		return Result{}, err
	}
	if !resp.Success || resp.Data.DiskSize <= 0 {
		return Result{}, Rejected()
	}
	// GetDetails: total = diskSize, used = diskSize - freeDiskSize. A negative
	// freeDiskSize is a real over-quota answer, not a corrupt one.
	total := resp.Data.DiskSize * yun139MB
	used := (resp.Data.DiskSize - resp.Data.FreeDiskSize) * yun139MB
	scope := "personal"
	if family {
		scope = "family"
	}
	result := Result{Scope: scope, Total: total, Used: used, OverQuota: used > total}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}

// post performs one signed request. Headers and the signature scheme follow
// drivers/139/util.go request(); the values are constant because the endpoint
// is a fixed PC web surface.
func (p *Yun139Provider) post(ctx context.Context, authorization string, family bool, body []byte) (yun139QuotaResponse, error) {
	var out yun139QuotaResponse
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	random := p.random
	if random == nil {
		random = yun139RandomString
	}
	ts := now().Format("2006-01-02 15:04:05")
	nonce := random(16)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return out, Invalid()
	}
	svcType := "1"
	if family {
		svcType = "2"
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CMS-DEVICE", "default")
	req.Header.Set("Authorization", "Basic "+authorization)
	req.Header.Set("mcloud-channel", "1000101")
	req.Header.Set("mcloud-client", "10701")
	req.Header.Set("mcloud-sign", fmt.Sprintf("%s,%s,%s", ts, nonce, yun139Sign(string(body), ts, nonce)))
	req.Header.Set("mcloud-version", "7.14.0")
	req.Header.Set("Origin", "https://yun.139.com")
	req.Header.Set("Referer", "https://yun.139.com/w/")
	req.Header.Set("x-DeviceInfo", "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||")
	req.Header.Set("x-huawei-channelSrc", "10000034")
	req.Header.Set("x-inner-ntwk", "2")
	req.Header.Set("x-m4c-caller", "PC")
	req.Header.Set("x-m4c-src", "10002")
	req.Header.Set("x-SvcType", svcType)
	req.Header.Set("Inner-Hcy-Router-Https", "1")
	res, err := p.client.Do(req)
	if err != nil {
		return out, Rejected()
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		return out, Rejected()
	}
	decoded, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return out, Rejected()
	}
	if err := json.Unmarshal(decoded, &out); err != nil {
		return out, Rejected()
	}
	return out, nil
}

// yun139Sign reproduces calSign from drivers/139/util.go: percent-encode the
// body, sort its characters, base64 that, then chain two MD5 digests and upper
// case the result. The live endpoint accepted this exact construction.
func yun139Sign(body, ts, nonce string) string {
	encoded := yun139EncodeURIComponent(body)
	chars := strings.Split(encoded, "")
	sort.Strings(chars)
	digest := base64.StdEncoding.EncodeToString([]byte(strings.Join(chars, "")))
	chained := yun139MD5(digest) + yun139MD5(ts+":"+nonce)
	return strings.ToUpper(yun139MD5(chained))
}

func yun139MD5(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// yun139EncodeURIComponent matches JavaScript encodeURIComponent, which is what
// calSign applies before sorting. url.QueryEscape is not equivalent: it encodes
// a space as "+" and leaves different characters unescaped.
func yun139EncodeURIComponent(value string) string {
	const unreserved = "-_.!~*'()"
	var out strings.Builder
	out.Grow(len(value) * 3)
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte(unreserved, c) >= 0 {
			out.WriteByte(c)
			continue
		}
		out.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return out.String()
}

// yun139RandomString builds the nonce calSign mixes into the signature. The
// server echoes it back inside mcloud-sign, so any alphanumeric value works.
func yun139RandomString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if n <= 0 {
		return ""
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("a", n)
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}
