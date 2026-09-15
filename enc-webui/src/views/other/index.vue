<template>
  <div class="system-info-page scroll-y">
    <div class="admin-page system-info-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Runtime Overview</div>
          <div class="page-title">系统信息</div>
          <div class="page-subtitle">
            展示服务构建信息、运行时长与关键缓存命中情况，帮助定位预热与热数据利用率问题。
          </div>
        </div>
        <div class="page-actions">
          <el-button type="primary" plain :loading="refreshing" @click="loadAll">刷新</el-button>
        </div>
      </section>

      <div class="two-column-grid">
        <section class="panel-card">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">构建信息</div>
              <div class="panel-card__subtitle">版本与前端集成方式。</div>
            </div>
          </div>
          <div class="kv-grid">
            <div class="kv-row"><span>服务版本</span><strong>{{ buildInfo.version || '-' }}</strong></div>
            <div class="kv-row"><span>前端集成</span><strong>{{ buildInfo.embedded_web_ui ? '已内嵌' : '未内嵌' }}</strong></div>
            <div class="kv-row"><span>管理模式</span><strong>{{ buildInfo.management_mode || '-' }}</strong></div>
            <div class="kv-row"><span>运行时长</span><strong>{{ uptime || '-' }}</strong></div>
          </div>
        </section>

        <section class="panel-card panel-card--soft">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">预热与命中</div>
              <div class="panel-card__subtitle">扫描成功数会被当作命中率分母，真实命中单独统计。</div>
            </div>
          </div>
          <div class="kv-grid">
            <div class="kv-row"><span>预热成功</span><strong>{{ runtime.sched?.files_succeeded_total ?? 0 }}</strong></div>
            <div class="kv-row"><span>真实命中</span><strong>{{ runtime.sched?.consumer_hit_total ?? 0 }}</strong></div>
            <div class="kv-row"><span>命中率</span><strong>{{ hitRateText }}</strong></div>
            <div class="kv-row"><span>Range 探测</span><strong>{{ runtime.sched?.files_range_probed ?? 0 }}</strong></div>
            <div class="kv-row"><span>首帧预热入队</span><strong>{{ runtime.stream?.warmup_enqueue_count ?? 0 }}</strong></div>
          </div>
        </section>
      </div>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">缓存状态</div>
            <div class="panel-card__subtitle">解密块缓存、文件大小缓存与路径缓存的命中情况。</div>
          </div>
        </div>
        <div class="cache-grid">
          <div v-for="item in cacheCards" :key="item.title" class="metric-card">
            <div class="metric-card__title">{{ item.title }}</div>
            <div class="metric-card__content">{{ item.content }}</div>
          </div>
        </div>
      </section>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">播放统计</div>
            <div class="panel-card__subtitle">真实播放与删除事件（含 seek 次数与时长），供导出给 AI 分析。</div>
          </div>
          <div class="pb-actions">
            <el-button type="danger" plain size="small" @click="clearStats">清空</el-button>
            <el-button type="primary" plain :disabled="exportingStats" @click="exportStatsJson">
              {{ exportingStats ? '导出中...' : '导出 JSON' }}
            </el-button>
          </div>
        </div>
        <div class="pb-summary-grid">
          <div class="pb-summary">
            <div class="pb-summary__label">播放次数</div>
            <div class="pb-summary__value">{{ playbackSummary.played }}</div>
          </div>
          <div class="pb-summary">
            <div class="pb-summary__label">删除次数</div>
            <div class="pb-summary__value">{{ playbackSummary.deleted }}</div>
          </div>
          <div class="pb-summary">
            <div class="pb-summary__label">累计播放时长</div>
            <div class="pb-summary__value">{{ playbackSummary.durationText }}</div>
          </div>
          <div class="pb-summary">
            <div class="pb-summary__label">总 seek 次数</div>
            <div class="pb-summary__value">{{ playbackSummary.seeks }}</div>
          </div>
        </div>

        <el-tabs v-model="statsTab" class="pb-tabs">
          <el-tab-pane label="播放记录" name="playback">
            <div class="ff-chart-row">
              <div class="ff-chart-card">
                <div class="ff-chart-title">
                  首帧耗时 <span class="ff-chart-sub">header_latency_ms · p50 {{ p50Latency }}ms · p95 {{ p95Latency }}ms</span>
                </div>
                <canvas ref="latencyCanvas" class="ff-canvas" width="560" height="120" />
              </div>
              <div class="ff-chart-card">
                <div class="ff-chart-title">
                  下行速率 <span class="ff-chart-sub">MiB/s · 峰值 {{ peakMbps }}MiB/s</span>
                </div>
                <canvas ref="mbpsCanvas" class="ff-canvas" width="560" height="120" />
              </div>
            </div>
            <el-table :data="playbacks" size="small" max-height="360" empty-text="暂无播放记录">
              <el-table-column prop="path" label="路径" min-width="200" show-overflow-tooltip />
              <el-table-column prop="provider" label="源" min-width="120" show-overflow-tooltip />
              <el-table-column label="时长" width="90">
                <template #default="{ row }">{{ fmtDuration(row.duration_secs) }}</template>
              </el-table-column>
              <el-table-column label="首帧ms" width="80" align="right">
                <template #default="{ row }">{{ row.header_latency_ms ? Math.round(row.header_latency_ms) : '-' }}</template>
              </el-table-column>
              <el-table-column label="MiB/s" width="80" align="right">
                <template #default="{ row }">{{ row.mbps ? row.mbps.toFixed(1) : '-' }}</template>
              </el-table-column>
              <el-table-column prop="seek_count" label="seek" width="70" align="center" />
              <el-table-column label="字节" width="110" align="right">
                <template #default="{ row }">{{ fmtBytes(row.bytes_served) }}</template>
              </el-table-column>
              <el-table-column label="时间" width="150">
                <template #default="{ row }">{{ fmtTime(row.played_at) }}</template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="删除记录" name="deletion">
            <el-table :data="deletions" size="small" max-height="360" empty-text="暂无删除记录">
              <el-table-column prop="path" label="路径" min-width="200" show-overflow-tooltip />
              <el-table-column label="距上次播放" width="140">
                <template #default="{ row }">{{ fmtSince(row.since_last_play_secs) }}</template>
              </el-table-column>
              <el-table-column label="删除时间" width="150">
                <template #default="{ row }">{{ fmtTime(row.deleted_at) }}</template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessageBox } from 'element-plus'
import { clearPlaybackStatsReq, getBuildInfoReq, getPlaybackStatsReq, getStatsReq } from '@/api/user'

const buildInfo = reactive({})
const runtime = reactive({
  uptime: '',
  sched: {},
  stream: {},
  cache: {}
})
const refreshing = ref(false)
let timer = null

// 播放/删除统计
const statsTab = ref('playback')
const playbacks = ref([])
const deletions = ref([])

// 首帧/速率曲线（canvas 自绘，零外部依赖）
const latencyCanvas = ref(null)
const mbpsCanvas = ref(null)

// 取有首帧记录的播放事件，按时间升序
const latencySeries = computed(() => {
  const rows = (playbacks.value || []).filter(r => r.header_latency_ms > 0)
  rows.sort((a, b) => new Date(a.played_at) - new Date(b.played_at))
  return rows.map(r => ({ t: new Date(r.played_at), v: r.header_latency_ms })).slice(-200)
})
const mbpsSeries = computed(() => {
  const rows = (playbacks.value || []).filter(r => r.mbps > 0)
  rows.sort((a, b) => new Date(a.played_at) - new Date(b.played_at))
  return rows.map(r => ({ t: new Date(r.played_at), v: r.mbps })).slice(-200)
})
// p50/p95 of first-frame latency
const p50Latency = computed(() => percentile(latencySeries.value.map(s => s.v), 0.5))
const p95Latency = computed(() => percentile(latencySeries.value.map(s => s.v), 0.95))
const peakMbps = computed(() => {
  const vs = mbpsSeries.value.map(s => s.v)
  return vs.length ? Math.max(...vs).toFixed(1) : '-'
})

const percentile = (arr, q) => {
  if (!arr.length) return '-'
  const sorted = [...arr].sort((a, b) => a - b)
  const idx = Math.min(sorted.length - 1, Math.round(q * (sorted.length - 1)))
  return Math.round(sorted[idx])
}

const drawSeries = (canvas, series, opts) => {
  if (!canvas || !series.length) return
  const ctx = canvas.getContext('2d')
  const W = canvas.width, H = canvas.height
  const padL = 52, padR = 12, padT = 12, padB = 20
  ctx.clearRect(0, 0, W, H)

  // 值域
  let maxV = 0
  for (const s of series) if (s.v > maxV) maxV = s.v
  if (maxV <= 0) return
  // 取整到好看的上界（1/2/5 步长）
  const niceCeil = (v) => {
    if (v <= 0) return 1
    const mag = 10**Math.floor(Math.log10(v))
    const norm = v / mag
    const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10
    return nice * mag
  }
  maxV = niceCeil(maxV)

  // 时间轴
  const t0 = series[0].t.getTime(), t1 = series[series.length - 1].t.getTime()
  const span = Math.max(t1 - t0, 1)
  const x = s => padL + (s.t.getTime() - t0) / span * (W - padL - padR)
  const y = v => padT + (H - padT - padB) * (1 - v / maxV)

  // 网格 + Y 轴刻度（均分 4 段，5 条刻度线带数值标签）
  const ticks = 4
  ctx.strokeStyle = 'rgba(128,128,128,0.18)'
  ctx.lineWidth = 1
  ctx.font = '10px sans-serif'
  ctx.textAlign = 'right'
  ctx.textBaseline = 'middle'
  for (let i = 0; i <= ticks; i++) {
    const v = maxV * i / ticks
    const yy = y(v)
    ctx.beginPath()
    ctx.moveTo(padL, yy); ctx.lineTo(W - padR, yy)
    ctx.stroke()
    ctx.fillStyle = 'rgba(150,150,150,0.9)'
    ctx.fillText(opts.unit ? `${String(Math.round(v * 100) / 100)}${opts.unit}` : String(Math.round(v * 100) / 100), padL - 6, yy)
  }

  // X 轴时间刻度（最多 5 个，避免拥挤）
  ctx.textBaseline = 'top'
  ctx.textAlign = 'center'
  const xTicks = 4
  for (let i = 0; i <= xTicks; i++) {
    const ts = new Date(t0 + span * i / xTicks)
    const xx = padL + (W - padL - padR) * i / xTicks
    ctx.fillStyle = 'rgba(150,150,150,0.9)'
    ctx.fillText(`${ts.getHours()}:${String(ts.getMinutes()).padStart(2, '0')}`, xx, H - padB + 4)
  }

  // 折线
  ctx.strokeStyle = opts.color || '#409eff'
  ctx.lineWidth = 1.5
  ctx.lineJoin = 'round'
  ctx.beginPath()
  series.forEach((s, i) => {
    const px = x(s), py = y(s.v)
    if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py)
  })
  ctx.stroke()

  // 数据点：圆点 + 数值标签（数据点上方小字号）
  ctx.textAlign = 'center'
  ctx.textBaseline = 'bottom'
  const step = Math.max(1, Math.ceil(series.length / 60))
  series.forEach((s, i) => {
    if (i % step !== 0 && i !== series.length - 1) return
    const px = x(s), py = y(s.v)
    ctx.beginPath()
    ctx.arc(px, py, 2.5, 0, Math.PI * 2)
    ctx.fillStyle = opts.color || '#409eff'
    ctx.fill()
    // 数值标签：单位可选
    const valText = opts.unit
      ? `${Math.round(s.v * 100) / 100}${opts.unit}`
      : String(Math.round(s.v))
    ctx.font = '9px sans-serif'
    ctx.fillStyle = opts.labelColor || 'rgba(90,90,90,0.95)'
    ctx.fillText(valText, px, py - 5)
  })

  // Y 轴标题（单位）
  if (opts.unit) {
    ctx.save()
    ctx.translate(12, padT + 2)
    ctx.font = '10px sans-serif'
    ctx.textAlign = 'left'
    ctx.textBaseline = 'top'
    ctx.fillStyle = 'rgba(150,150,150,0.9)'
    ctx.fillText(opts.unit, 0, 0)
    ctx.restore()
  }
}

const loadPlaybackStats = async () => {
  try {
    const res = await getPlaybackStatsReq({ reqLoading: false })
    const data = res?.data || {}
    playbacks.value = data.playbacks || []
    deletions.value = data.deletions || []
  } catch {
    /* silent */
  }
}

const exportingStats = ref(false)

// 播放数据变化后重绘首帧/速率曲线（nextTick 保证 canvas 已挂载）
watch([latencySeries, mbpsSeries], async () => {
  await nextTick()
  drawSeries(latencyCanvas.value, latencySeries.value, { color: '#409eff', unit: 'ms', labelColor: 'rgba(64,158,255,0.95)' })
  drawSeries(mbpsCanvas.value, mbpsSeries.value, { color: '#67c23a', unit: 'M', labelColor: 'rgba(103,194,58,0.95)' })
})

// 清空全部播放/删除统计（重新积累）。带确认。
const clearStats = async () => {
  try {
    await ElMessageBox.confirm('确定清空全部播放/删除统计？此操作不可撤销。', '清空统计', {
      confirmButtonText: '清空',
      cancelButtonText: '取消',
      type: 'warning'
    })
  } catch {
    return // 用户取消
  }
  try {
    await clearPlaybackStatsReq({ reqLoading: false })
    playbacks.value = []
    deletions.value = []
  } catch {
    /* silent */
  }
}

// 导出全量播放/删除统计为 JSON 文件（走管理 JWT，无需独立密码）。
const exportStatsJson = async () => {
  exportingStats.value = true
  try {
    const res = await getPlaybackStatsReq({
      reqLoading: false,
      params: { limit: 0 }
    })
    const data = res?.data || {}
    const payload = {
      exported_at: new Date().toISOString(),
      playbacks: data.playbacks || [],
      deletions: data.deletions || []
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json'
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `playback-stats-${new Date().toISOString().slice(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  } catch {
    /* silent */
  } finally {
    exportingStats.value = false
  }
}

const playbackSummary = computed(() => {
  let played = 0
  let deleted = 0
  let duration = 0
  let seeks = 0
  for (const p of playbacks.value) {
    played += 1
    duration += Number(p.duration_secs) || 0
    seeks += Number(p.seek_count) || 0
  }
  deleted = deletions.value.length
  return {
    played,
    deleted,
    seeks,
    durationText: fmtDuration(duration)
  }
})

const fmtDuration = (secs) => {
  const s = Number(secs) || 0
  if (s < 60) return `${s.toFixed(0)}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

const fmtBytes = (b) => {
  const n = Number(b) || 0
  if (n < 1024) return `${n}B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)}MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)}GB`
}

const fmtSince = (secs) => {
  const n = Number(secs) || 0
  if (n < 0) return '从未播放'
  return fmtDuration(n)
}

const fmtTime = (ts) => {
  if (!ts) return '-'
  const d = new Date(Number(ts) * 1000)
  if (Number.isNaN(d.getTime())) return String(ts)
  const p = (v) => String(v).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

const loadAll = async () => {
  refreshing.value = true
  try {
    const [statsRes, buildRes] = await Promise.all([
      getStatsReq({ reqLoading: false }),
      getBuildInfoReq({ reqLoading: false })
    ])
    const data = statsRes?.data || {}
    runtime.uptime = data.uptime || ''
    runtime.sched = data.probe_scheduler || {}
    runtime.stream = data.stream || {}
    runtime.cache = data.cache || {}
    Object.assign(buildInfo, buildRes?.data || {})
  } catch {
    /* silent */
  } finally {
    refreshing.value = false
  }
}

const hitRateText = computed(() => {
  const rate = Number(runtime.sched?.consumer_hit_rate) || 0
  return `${(rate * 100).toFixed(1)}%`
})

const cacheCards = computed(() => {
  const dec = runtime.cache?.decrypted_block_cache || {}
  const fsz = runtime.cache?.file_size_cache || {}
  const pc = runtime.cache?.path_cache || {}
  const cards = []
  if (dec.enabled !== undefined) {
    cards.push({
      title: '解密块缓存',
      content: dec.enabled
        ? `命中 ${dec.hit_count || 0} · 未命中 ${dec.miss_count || 0} · ${((dec.used_bytes || 0) / 1048576).toFixed(0)}MB/${((dec.max_bytes || 0) / 1048576).toFixed(0)}MB`
        : '已禁用'
    })
  }
  if (fsz) {
    cards.push({
      title: '文件大小缓存',
      content: `命中 ${fsz.hits || fsz.hit_count || 0} · 未命中 ${fsz.misses || fsz.miss_count || 0}`
    })
  }
  if (pc) {
    cards.push({
      title: '路径缓存',
      content: `命中 ${pc.hits || pc.hit_count || 0} · 未命中 ${pc.misses || pc.miss_count || 0}`
    })
  }
  if (!cards.length) cards.push({ title: '缓存', content: '暂无数据' })
  return cards
})

onMounted(() => {
  loadAll()
  loadPlaybackStats()
  timer = window.setInterval(() => {
    loadAll()
    loadPlaybackStats()
  }, 10000)
})
onUnmounted(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped lang="scss">
.system-info-page {
  padding: 6px 0 30px;
  animation: page-fade-in 0.4s ease;
}

@keyframes page-fade-in {
  from {
    opacity: 0;
    transform: translateY(6px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.system-info-shell {
  max-width: 1320px;
  margin: 0 auto;
}

.kv-grid {
  display: grid;
  gap: 4px;
}

.kv-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 12px 14px;
  border-radius: var(--app-radius-sm);
  background: var(--app-surface-muted);
  color: var(--el-text-color-regular);
  font-size: 13px;
}

.kv-row span {
  color: var(--el-text-color-secondary);
}

.kv-row strong {
  color: var(--el-text-color-primary);
  font-variant-numeric: tabular-nums;
}

.cache-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 14px;
}

.metric-card {
  border: 1px solid var(--app-border-color);
  border-radius: var(--app-radius-lg);
  background: linear-gradient(180deg, var(--app-surface-soft), var(--app-surface));
  box-shadow: var(--app-shadow-md);
  padding: 16px;
  transition: transform 0.22s ease, box-shadow 0.22s ease, border-color 0.22s ease;
}

.metric-card:hover {
  transform: translateY(-3px);
  border-color: var(--app-border-strong);
  box-shadow: var(--app-glow-primary);
}

.pb-summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.pb-summary {
  border: 1px solid var(--app-border-color);
  border-radius: var(--app-radius-md);
  background: linear-gradient(180deg, var(--app-surface-soft), var(--app-surface));
  padding: 14px 16px;
}

.pb-summary__label {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
}

.pb-summary__value {
  font-size: 20px;
  font-weight: 700;
  color: var(--el-color-primary);
  font-variant-numeric: tabular-nums;
}

.pb-tabs {
  margin-top: 4px;
}

.ff-chart-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.ff-chart-card {
  flex: 1 1 320px;
  max-width: 560px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
  padding: 8px 10px;
  background: var(--el-bg-color);
}
.ff-chart-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--el-text-color-primary);
  margin-bottom: 6px;
}
.ff-chart-sub {
  font-weight: 400;
  color: var(--el-text-color-secondary);
  margin-left: 6px;
}
.ff-canvas {
  display: block;
  width: 100%;
  height: 120px;
}

.pb-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.metric-card__title {
  margin-bottom: 10px;
  color: var(--el-text-color-primary);
  font-size: 14px;
  font-weight: 700;
}

.metric-card__content {
  color: var(--el-text-color-regular);
  font-size: 12px;
  line-height: 1.8;
  font-variant-numeric: tabular-nums;
}
</style>
