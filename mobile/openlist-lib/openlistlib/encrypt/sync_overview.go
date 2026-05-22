package encrypt

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func maskSyncBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return raw
	}
	host := strings.TrimSpace(u.Host)
	if host == "" {
		return raw
	}
	scheme := strings.TrimSpace(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + host
}

func unixToRFC3339(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func (p *ProxyServer) handleSyncOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data := map[string]interface{}{
		"enabled":             false,
		"sync_mode":           dbExportSyncModeSizeOnlyDegrade,
		"base_url_masked":     "",
		"last_success_at":     "",
		"last_cycle_imported": 0,
		"total_imported":      int64(0),
		"lag_seconds":         int64(0),
		"last_error":          "",
		"checkpoint": map[string]interface{}{
			"meta":     map[string]interface{}{"since": int64(0), "cursor": ""},
			"strategy": map[string]interface{}{"since": int64(0), "cursor": ""},
			"range":    map[string]interface{}{"since": int64(0), "cursor": ""},
		},
		"local_counts": map[string]interface{}{
			"size_entries":         0,
			"strategy_entries":     0,
			"range_compat_entries": 0,
			"range_probe_targets":  0,
		},
		"recent_cycles": []LocalSyncCycleRecord{},
	}

	if p != nil && p.config != nil {
		data["enabled"] = p.config.EnableDBExportSync
		data["base_url_masked"] = maskSyncBaseURL(normalizeDBExportBaseURL(p.config.DBExportBaseURL))
	}

	if p != nil && p.localStore != nil {
		sizeCount, strategyCount, rangeCompatCount, rangeProbeCount, err := p.localStore.CountsExtended()
		if err == nil {
			data["local_counts"] = map[string]interface{}{
				"size_entries":         sizeCount,
				"strategy_entries":     strategyCount,
				"range_compat_entries": rangeCompatCount,
				"range_probe_targets":  rangeProbeCount,
			}
		}

		if status, err := p.localStore.GetSyncStatus(dbExportSyncStatusName); err == nil && status != nil {
			data["sync_mode"] = status.SyncMode
			if strings.TrimSpace(status.SyncMode) == "" {
				data["sync_mode"] = dbExportSyncModeSizeOnlyDegrade
			}
			data["last_success_at"] = unixToRFC3339(status.LastSuccessAt)
			data["last_cycle_imported"] = status.LastCycleImported
			data["total_imported"] = status.TotalImported
			data["last_error"] = status.LastError
		}

		if cycles, err := p.localStore.ListRecentSyncCycles(dbExportSyncStatusName, 20); err == nil {
			data["recent_cycles"] = cycles
		}

		metaSince, metaCursor, _ := p.localStore.GetSyncCheckpoint(dbExportCheckpointName)
		strategySince, strategyCursor, _ := p.localStore.GetSyncCheckpoint(dbExportStrategyCheckpointName)
		rangeSince, rangeCursor, _ := p.localStore.GetSyncCheckpoint(dbExportRangeCheckpointName)
		data["checkpoint"] = map[string]interface{}{
			"meta":     map[string]interface{}{"since": metaSince, "cursor": metaCursor},
			"strategy": map[string]interface{}{"since": strategySince, "cursor": strategyCursor},
			"range":    map[string]interface{}{"since": rangeSince, "cursor": rangeCursor},
		}
		if metaSince > 0 {
			lag := time.Now().Unix() - metaSince
			if lag < 0 {
				lag = 0
			}
			data["lag_seconds"] = lag
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": data,
	})
}

const syncStatsPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sync Stats</title>
  <style>
    :root {
      --bg: #f7f8fb;
      --card: #ffffff;
      --ink: #19202a;
      --muted: #5c6778;
      --ok: #0b8f55;
      --warn: #b35600;
      --bad: #bf2f45;
      --line: #d9dfeb;
      --accent: #1f6feb;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Segoe UI", "PingFang SC", sans-serif; background: var(--bg); color: var(--ink); }
    .wrap { max-width: 1080px; margin: 0 auto; padding: 16px; }
    .head { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom: 12px; }
    .head h1 { margin: 0; font-size: 20px; }
    .actions { display:flex; gap:8px; align-items:center; }
    button { border: 1px solid var(--line); background: var(--card); color: var(--ink); padding: 6px 10px; border-radius: 8px; cursor: pointer; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit,minmax(230px,1fr)); gap:10px; }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 12px; }
    .k { color: var(--muted); font-size: 12px; margin-bottom: 6px; }
    .v { font-size: 22px; font-weight: 600; }
    .hint { font-size: 12px; color: var(--muted); }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .bad { color: var(--bad); }
    table { width: 100%; border-collapse: collapse; }
    th,td { border-bottom: 1px solid var(--line); padding: 8px 6px; text-align: left; font-size: 13px; }
    th { color: var(--muted); font-weight: 600; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="head">
      <h1>DB_EXPORT 同步统计</h1>
      <div class="actions">
        <label class="hint">自动刷新 5s</label>
        <button id="refresh">刷新</button>
      </div>
    </div>

    <div class="grid">
      <div class="card"><div class="k">同步状态</div><div class="v" id="status">-</div><div class="hint" id="mode">-</div></div>
      <div class="card"><div class="k">最近成功</div><div class="v" id="lastSuccess">-</div><div class="hint">RFC3339</div></div>
      <div class="card"><div class="k">滞后(秒)</div><div class="v" id="lag">0</div><div class="hint">按 meta checkpoint 估算</div></div>
      <div class="card"><div class="k">本轮 / 累计导入</div><div class="v" id="imported">0 / 0</div><div class="hint" id="lastError">无错误</div></div>
    </div>

    <div class="grid" style="margin-top:10px;">
      <div class="card"><div class="k">size entries</div><div class="v" id="sizeCount">0</div></div>
      <div class="card"><div class="k">strategy entries</div><div class="v" id="strategyCount">0</div></div>
      <div class="card"><div class="k">range compat entries</div><div class="v" id="rangeCompatCount">0</div></div>
      <div class="card"><div class="k">range probe targets</div><div class="v" id="rangeProbeCount">0</div></div>
    </div>

    <div class="card" style="margin-top:10px;">
      <div class="k">Checkpoint</div>
      <div class="mono hint" id="checkpoint">-</div>
    </div>

    <div class="card" style="margin-top:10px;">
      <div class="k">最近同步轮次</div>
      <table>
        <thead><tr><th>时间</th><th>导入</th><th>状态</th><th>错误摘要</th></tr></thead>
        <tbody id="cycles"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function loadOverview() {
      const res = await fetch('/api/encrypt/sync/overview', { cache: 'no-store' });
      const payload = await res.json();
      const d = payload && payload.data ? payload.data : {};
      const enabled = !!d.enabled;
      const status = enabled ? '启用' : '关闭';
      document.getElementById('status').textContent = status;
      document.getElementById('status').className = enabled ? 'v ok' : 'v warn';
      document.getElementById('mode').textContent = '模式: ' + (d.sync_mode || '-');
      document.getElementById('lastSuccess').textContent = d.last_success_at || '-';
      document.getElementById('lag').textContent = String(d.lag_seconds || 0);
      document.getElementById('imported').textContent = String(d.last_cycle_imported || 0) + ' / ' + String(d.total_imported || 0);
      const err = (d.last_error || '').trim();
      document.getElementById('lastError').textContent = err ? err : '无错误';
      document.getElementById('lastError').className = err ? 'hint bad' : 'hint';

      const c = d.local_counts || {};
      document.getElementById('sizeCount').textContent = String(c.size_entries || 0);
      document.getElementById('strategyCount').textContent = String(c.strategy_entries || 0);
      document.getElementById('rangeCompatCount').textContent = String(c.range_compat_entries || 0);
      document.getElementById('rangeProbeCount').textContent = String(c.range_probe_targets || 0);

      const cp = d.checkpoint || {};
      const line = [
        'meta=' + JSON.stringify(cp.meta || {}),
        'strategy=' + JSON.stringify(cp.strategy || {}),
        'range=' + JSON.stringify(cp.range || {})
      ].join(' | ');
      document.getElementById('checkpoint').textContent = line;

      const cycles = Array.isArray(d.recent_cycles) ? d.recent_cycles : [];
      const body = document.getElementById('cycles');
      body.innerHTML = cycles.map(cy => {
        const ts = cy.cycle_at ? new Date(cy.cycle_at * 1000).toISOString() : '-';
        const ok = cy.ok ? '<span class="ok">OK</span>' : '<span class="bad">FAIL</span>';
        const errText = (cy.error_summary || '').replace(/[<>]/g, '');
        return '<tr><td class="mono">' + ts + '</td><td>' + String(cy.imported || 0) + '</td><td>' + ok + '</td><td>' + (errText || '-') + '</td></tr>';
      }).join('');
    }

    document.getElementById('refresh').addEventListener('click', () => loadOverview().catch(console.error));
    loadOverview().catch(console.error);
    setInterval(() => loadOverview().catch(console.error), 5000);
  </script>
</body>
</html>`

func (p *ProxyServer) handleSyncStatsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(syncStatsPageHTML))
}
