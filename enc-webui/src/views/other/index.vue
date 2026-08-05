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
            <div class="kv-row"><span>预热成功</span><strong>{{ sched.files_succeeded_total ?? 0 }}</strong></div>
            <div class="kv-row"><span>真实命中</span><strong>{{ sched.consumer_hit_total ?? 0 }}</strong></div>
            <div class="kv-row"><span>命中率</span><strong>{{ hitRateText }}</strong></div>
            <div class="kv-row"><span>Range 探测</span><strong>{{ sched.files_range_probed ?? 0 }}</strong></div>
            <div class="kv-row"><span>首帧预热入队</span><strong>{{ stream.warmup_enqueue_count ?? 0 }}</strong></div>
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
            <el-table :data="playbacks" size="small" max-height="360" empty-text="暂无播放记录">
              <el-table-column prop="path" label="路径" min-width="200" show-overflow-tooltip />
              <el-table-column prop="provider" label="源" min-width="120" show-overflow-tooltip />
              <el-table-column label="时长" width="90">
                <template #default="{ row }">{{ fmtDuration(row.duration_secs) }}</template>
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
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { getPlaybackStatsReq, getStatsReq } from '@/api/user'

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
    const res = await getStatsReq({ reqLoading: false })
    const data = res?.data || {}
    runtime.uptime = data.uptime || ''
    runtime.sched = data.probe_scheduler || {}
    runtime.stream = data.stream || {}
    runtime.cache = data.cache || {}
  } catch {
    /* silent */
  } finally {
    refreshing.value = false
  }
}

const hitRateText = computed(() => {
  const rate = Number(runtime.sched.consumer_hit_rate) || 0
  return `${(rate * 100).toFixed(1)}%`
})

const cacheCards = computed(() => {
  const dec = runtime.cache.decrypted_block_cache || {}
  const fsz = runtime.cache.file_size_cache || {}
  const pc = runtime.cache.path_cache || {}
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
