package encrypt

import (
	"net/http/httptest"
	"testing"
	"time"
)

func resetDualNetworkState() {
	SetEncryptDualNetworkMarks(0, 0, false)
	globalDualNetworkLatency.mu.Lock()
	globalDualNetworkLatency.entries = make(map[string]*rttEntry)
	globalDualNetworkLatency.lastProbeAt = make(map[string]time.Time)
	globalDualNetworkLatency.negativeHost = make(map[string]time.Time)
	globalDualNetworkLatency.mu.Unlock()
	hostMarkHint.mu.Lock()
	hostMarkHint.hints = make(map[string]uint32)
	hostMarkHint.mu.Unlock()
}

func TestDualNetworkDisabledIsNoOp(t *testing.T) {
	resetDualNetworkState()
	// 默认关闭：chooseNetwork 必须返回空路径（不绑定）。
	path := globalDualNetworkLatency.chooseNetwork("unicom", dualNetworkPrefAuto)
	if path.mark != dualNetworkMarkNone {
		t.Fatalf("expected no binding when disabled, got mark=%d", path.mark)
	}
}

func TestDualNetworkChoosePrefersLowerRTT(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(100, 200, true)

	globalDualNetworkLatency.mu.Lock()
	globalDualNetworkLatency.entries["unicom"] = &rttEntry{
		provider: "unicom",
		host:     "tjdownload.pan.wo.cn",
		wifiRTT:  200 * time.Millisecond,
		cellRTT:  80 * time.Millisecond,
		updated:  time.Now(),
	}
	globalDualNetworkLatency.mu.Unlock()

	path := globalDualNetworkLatency.chooseNetwork("unicom", dualNetworkPrefAuto)
	if path.kind != "cell" || path.mark != 200 {
		t.Fatalf("expected cell (lower RTT), got kind=%s mark=%d", path.kind, path.mark)
	}
}

func TestDualNetworkOnlyOneNetworkBindsIt(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(100, 0, true) // 只有 WiFi 可绑定

	path := globalDualNetworkLatency.chooseNetwork("unknown_provider", dualNetworkPrefAuto)
	if path.kind != "wifi" || path.mark != 100 {
		t.Fatalf("expected wifi binding when only wifi available, got kind=%s mark=%d", path.kind, path.mark)
	}
}

func TestDualNetworkFallbackWhenPreferredUnavailable(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(0, 200, true) // 只有蜂窝可绑定

	// WiFi RTT 更低，但 WiFi mark 为 0（不可绑定）→ 应回退到蜂窝。
	globalDualNetworkLatency.mu.Lock()
	globalDualNetworkLatency.entries["baidu"] = &rttEntry{
		provider: "baidu",
		host:     "d.pcs.baidu.com",
		wifiRTT:  30 * time.Millisecond,
		cellRTT:  90 * time.Millisecond,
		updated:  time.Now(),
	}
	globalDualNetworkLatency.mu.Unlock()

	path := globalDualNetworkLatency.chooseNetwork("baidu", dualNetworkPrefAuto)
	if path.kind != "cell" || path.mark != 200 {
		t.Fatalf("expected cell fallback when wifi unbindable, got kind=%s mark=%d", path.kind, path.mark)
	}
}

func TestDualNetworkWiFiPreferenceWithHysteresis(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(100, 200, true)

	// 蜂窝快 80ms（低于 100ms 迟滞阈值）→ wifi 优先仍选 WiFi。
	globalDualNetworkLatency.mu.Lock()
	globalDualNetworkLatency.entries["wifi_first"] = &rttEntry{
		provider: "wifi_first", host: "cdn.example.com",
		wifiRTT: 200 * time.Millisecond, cellRTT: 120 * time.Millisecond, updated: time.Now(),
	}
	globalDualNetworkLatency.mu.Unlock()
	path := globalDualNetworkLatency.chooseNetwork("wifi_first", dualNetworkPrefWiFi)
	if path.kind != "wifi" || path.mark != 100 {
		t.Fatalf("wifi priority should stay on wifi within hysteresis, got kind=%s", path.kind)
	}

	// 蜂窝快 199ms（超过 100ms 迟滞）→ wifi 优先切到蜂窝。
	globalDualNetworkLatency.mu.Lock()
	globalDualNetworkLatency.entries["wifi_first"].cellRTT = 1 * time.Millisecond
	globalDualNetworkLatency.mu.Unlock()
	path = globalDualNetworkLatency.chooseNetwork("wifi_first", dualNetworkPrefWiFi)
	if path.kind != "cell" || path.mark != 200 {
		t.Fatalf("wifi priority should switch to cell when much faster, got kind=%s", path.kind)
	}
}

func TestDualNetworkProbeThrottle(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(100, 200, true)

	if !globalDualNetworkLatency.shouldProbe("unicom", time.Minute) {
		t.Fatalf("expected first probe allowed")
	}
	globalDualNetworkLatency.noteProbed("unicom")
	if globalDualNetworkLatency.shouldProbe("unicom", time.Hour) {
		t.Fatalf("expected probe throttled within interval")
	}
}

func TestDualNetworkNegativeBlocked(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(100, 200, true)

	globalDualNetworkLatency.markNegative("tjdownload.pan.wo.cn")
	if !globalDualNetworkLatency.negativeBlocked("tjdownload.pan.wo.cn") {
		t.Fatalf("expected negative-blocked host to be skipped")
	}
}

func TestDualNetworkStatusJSON(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(0x10000000, 0x20000000, true)
	jsonStr := GetEncryptDualNetworkStatusJson()
	if jsonStr == "" || jsonStr == "{}" {
		t.Fatalf("expected non-empty status JSON, got %q", jsonStr)
	}
	// sanity: enabled + wifi bound should appear
	for _, want := range []string{`"enabled":true`, `"fwmark":268435456`, `"bound":true`} {
		if !containsStr(jsonStr, want) {
			t.Fatalf("expected %q in status JSON: %s", want, jsonStr)
		}
	}
}

func TestDualNetworkResolverIntegratesWithoutProvider(t *testing.T) {
	resetDualNetworkState()
	SetEncryptDualNetworkMarks(0x10000000, 0x20000000, true)
	// 控制面请求（无 provider）不应触发绑定或 panic。
	req := httptest.NewRequest("GET", "http://192.168.1.10:5244/dav/", nil)
	resolver := newProxyResolver(&ProxyConfig{
		AlistHost:               "192.168.1.10",
		AlistPort:               5244,
		EnableLocalBypass:       true,
		RoutingMode:             routingModeByProvider,
		RoutingUnmatchedDefault: routingActionProxy,
	})
	if _, err := resolver(req); err != nil {
		t.Fatalf("resolver returned err: %v", err)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
