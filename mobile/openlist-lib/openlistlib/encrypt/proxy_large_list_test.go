package encrypt

import (
	"fmt"
	"strings"
	"testing"
)

// countResponses 统计改写后 XML 里的条目数：每个条目都含一条
// "<D:status>HTTP/1.1 200 OK</D:status>"（status 原样保留），前缀不依赖
// 编码器是否保留 <D:> 名字空间。
func countResponses(xml string) int {
	return strings.Count(xml, "HTTP/1.1 200 OK")
}

// buildLargePropfindXML 生成含 n 个文件条目的 PROPFIND 207 multistatus，
// href 使用真实加密名（EncodeName(password, 明文名) + 后缀），size 非零。
func buildLargePropfindXML(t *testing.T, n int, password, suffix string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><D:multistatus xmlns:D="DAV:" xmlns:ns1="urn:schemas-microsoft-com:">
`)
	for i := 0; i < n; i++ {
		plain := fmt.Sprintf("测试文件%06d", i) // 中文名更能暴露字节/URL 转义问题
		encName := EncodeName(password, EncTypeAESCTR, plain)
		fmt.Fprintf(&b, "<D:response><D:href>/dav/电影/%s%s</D:href><D:propstat><D:prop><D:getcontentlength>%d</D:getcontentlength></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n",
			encName, suffix, i+1024)
	}
	b.WriteString("</D:multistatus>")
	return b.String()
}

// TestLargePropfindDecryptsEveryName 大列表"名字解密不丢、不误"：
//  1. 预算内（未超限）：逐条回填 fileCache，显示名全部正确解密；
//  2. 输出条数与输入一致，无残留密文/无 orig_ 误标。
func TestLargePropfindDecryptsEveryName(t *testing.T) {
	password := "test-pass-大列表-联云"
	suffix := ".bin"
	n := 3000
	src := buildLargePropfindXML(t, n, password, suffix)
	encPath := &EncryptPath{
		Path:     "/dav/电影/",
		Password: password,
		EncType:  EncTypeAESCTR,
		EncName:  true,
		Enable:   true,
	}
	p := &ProxyServer{config: &ProxyConfig{EnableSizeMap: true}}

	var out strings.Builder
	budget := &propfindRewriteBudget{}
	if err := p.processPropfindResponseBudget(strings.NewReader(src), &out, encPath, budget); err != nil {
		t.Fatalf("process budget: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("empty rewrite output")
	}
	decoded := out.String()
	if countResponses(decoded) != n {
		t.Fatalf("decoded response count=%d want=%d", countResponses(decoded), n)
	}
	for i := 0; i < n; i++ {
		plain := fmt.Sprintf("测试文件%06d", i)
		if !strings.Contains(decoded, plain) {
			t.Fatalf("plain %q not found in rewrite output at index %d", plain, i)
		}
	}
	if strings.Contains(decoded, "orig_") {
		t.Fatalf("unexpected orig_ marker in rewrite: %s", decoded)
	}
	if budget.entries != n {
		t.Fatalf("budget.entries=%d want=%d", budget.entries, n)
	}
}

// TestLargePropfindBudgetExhaustedStillDecrypts 预算耗尽（超大列表，比如单目录
// 超过 10 万条）时：改写/解密必须照常 100% 满足——这是"能完成、且名字全对"的
// 最低红线。此时不应再逐条写缓存（超大目录直通态），但输出条目数不能少。
func TestLargePropfindBudgetExhaustedStillDecrypts(t *testing.T) {
	password := "budget-exhausted-pw-联云"
	suffix := ".bin"
	n := 30
	src := buildLargePropfindXML(t, n, password, suffix)
	encPath := &EncryptPath{
		Path:     "/dav/目录/",
		Password: password,
		EncType:  EncTypeAESCTR,
		EncName:  true,
		Enable:   true,
	}
	// 预算初始即已达上限：等价于处于超大目录直通态。
	budget := &propfindRewriteBudget{entries: propdirHugeListEntries}
	if !budget.exceeded() {
		t.Fatal("budget should be exceeded")
	}
	var out strings.Builder
	p := &ProxyServer{config: &ProxyConfig{EnableSizeMap: true}}
	if err := p.processPropfindResponseBudget(strings.NewReader(src), &out, encPath, budget); err != nil {
		t.Fatalf("process at exhausted budget: %v", err)
	}
	decoded := out.String()
	if countResponses(decoded) != n {
		t.Fatalf("decoded count=%d want=%d (budget exhausted but names must not drop)", countResponses(decoded), n)
	}
	for i := 0; i < n; i++ {
		plain := fmt.Sprintf("测试文件%06d", i)
		if !strings.Contains(decoded, plain) {
			t.Fatalf("name %q missing when budget exhausted", plain)
		}
	}
}
