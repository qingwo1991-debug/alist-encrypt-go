<template>
  <div class="warm-page scroll-y">
    <div class="admin-page warm-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Preheat Overview</div>
          <div class="page-title">预热总览</div>
          <div class="page-subtitle">
            一眼看清预热规模、新鲜度、命中率与未命中原因，快速定位系统异常。
          </div>
        </div>
        <div class="page-actions">
          <el-button type="primary" plain :loading="loading" @click="loadAll">刷新</el-button>
        </div>
      </section>

      <!-- 4 关键指标 -->
      <div class="warm-hero-grid">
        <div class="warm-hero-card">
          <div class="warm-hero-card__label">预热文件总数</div>
          <div class="warm-hero-card__value">{{ sched.unique_warmed_files ?? '-' }}</div>
          <div class="warm-hero-card__meta">
            去重口径 · 真实被预热的文件数
            <template v-if="new24h > 0"> · 近 24h 新增 <strong style="color: var(--el-color-primary)">{{ new24h }}</strong></template>
          </div>
        </div>
        <div class="warm-hero-card">
          <div class="warm-hero-card__label">上次预热</div>
          <div class="warm-hero-card__value warm-hero-card__value--sm">{{ fmtTime(sched.last_success_at) || '-' }}</div>
          <div class="warm-hero-card__meta">
            距今 {{ lastSuccessAgo }}
            <template v-if="sched.last_failure_at"> · 失败 {{ fmtTime(sched.last_failure_at) }}</template>
          </div>
        </div>
        <div class="warm-hero-card">
          <div class="warm-hero-card__label">命中率</div>
          <div class="warm-hero-card__value" :class="hitRateClass">{{ hitRateText }}</div>
          <div class="warm-hero-card__meta">
            命中 {{ sched.unique_consumer_hits ?? 0 }} / 预热 {{ sched.unique_warmed_files ?? 0 }}
          </div>
        </div>
        <div class="warm-hero-card">
          <div class="warm-hero-card__label">预热新鲜度</div>
          <div class="warm-hero-card__value warm-hero-card__value--sm">{{ warmStateText }}</div>
          <div class="warm-hero-card__meta">
            ready {{ warmStateCounts.ready ?? 0 }} · stale {{ warmStateCounts.stale ?? 0 }} · invalid {{ warmStateCounts.invalid ?? 0 }}
          </div>
        </div>
      </div>

      <!-- 失败原因 Top -->
      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">未命中原因排行</div>
            <div class="panel-card__subtitle">按失败原因聚合统计，出现次数越多越值得优先处理。</div>
          </div>
        </div>
        <div v-if="failureRows.length === 0" class="empty-hint">暂无失败记录 🎉</div>
        <div v-else class="fail-rank">
          <div v-for="row in failureRows" :key="row.reason" class="fail-rank__row">
            <div class="fail-rank__bar-wrap">
              <div class="fail-rank__reason">{{ row.reason }}</div>
              <div class="fail-rank__bar">
                <div class="fail-rank__bar-inner" :style="{ width: row.pct + '%' }" :class="row.hot ? 'is-hot' : ''" />
              </div>
            </div>
            <div class="fail-rank__count">{{ row.count }} 次</div>
          </div>
        </div>
      </section>

      <!-- 预热明细 -->
      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">预热明细</div>
            <div class="panel-card__subtitle">每个文件的上次预热时间、命中次数与当前状态，可按状态筛选。</div>
          </div>
          <div class="page-actions">
            <el-select v-model="stateFilter" size="small" style="width: 130px" placeholder="全部状态">
              <el-option label="全部" value="" />
              <el-option label="ready" value="ready" />
              <el-option label="stale" value="stale" />
              <el-option label="invalid" value="invalid" />
            </el-select>
          </div>
        </div>
        <div class="table-scroll">
          <el-table :data="filteredWarm" size="small" max-height="480" empty-text="暂无预热明细">
            <el-table-column label="文件名" min-width="200" show-overflow-tooltip>
              <template #default="{ row }">{{ row.file_name || row.display_path }}</template>
            </el-table-column>
            <el-table-column label="状态" width="90" align="center">
              <template #default="{ row }">
                <el-tag :type="stateTagType(row.state)" size="small">{{ row.state || '-' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="上次预热" width="160">
              <template #default="{ row }">{{ fmtTime(row.finished_at) || '-' }}</template>
            </el-table-column>
            <el-table-column label="命中数" width="80" align="right">
              <template #default="{ row }">{{ row.consumer_hit_count ?? 0 }}</template>
            </el-table-column>
            <el-table-column label="上次命中" width="160">
              <template #default="{ row }">{{ fmtTime(row.last_consumer_hit_at) || '-' }}</template>
            </el-table-column>
            <el-table-column prop="source" label="来源" width="110" show-overflow-tooltip />
          </el-table>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { getStatsReq } from '@/api/user'

const sched = reactive({})
const loading = ref(false)
const stateFilter = ref('')
let timer = null

const fetchStats = async () => {
  try {
    const res = await getStatsReq({ reqLoading: false })
    const data = res?.data || {}
    Object.assign(sched, data.probe_scheduler || {})
  } catch {
    /* silent */
  }
}

const loadAll = async () => {
  loading.value = true
  await fetchStats()
  loading.value = false
}

const warmStateCounts = computed(() => sched.warm_state_counts || {})

// 上次成功预热距今时长（人类可读）
const lastSuccessAgo = computed(() => {
  const t = sched.last_success_at ? new Date(sched.last_success_at).getTime() : 0
  if (!t || Number.isNaN(t)) return '-'
  const diff = Math.max(0, Date.now() - t)
  const m = Math.floor(diff / 60000)
  if (m < 1) return '刚刚'
  if (m < 60) return `${m} 分钟`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h} 小时`
  const d = Math.floor(h / 24)
  return `${d} 天`
})

// 近 24 小时完成过预热的文件数（近似"新增/活跃"口径，来自 each file finished_at）
const new24h = computed(() => {
  const states = sched.current_warm_states || []
  if (!states.length) return 0
  const cutoff = Date.now() - 24 * 3600 * 1000
  return states.filter(s => {
    const t = s.finished_at ? new Date(s.finished_at).getTime() : 0
    return t >= cutoff
  }).length
})
const warmStateText = computed(() => {
  const c = warmStateCounts.value
  const ready = c.ready ?? 0
  const total = ready + (c.stale ?? 0) + (c.invalid ?? 0)
  if (!total) return '-'
  return `${Math.round((ready / total) * 100)}% 新鲜`
})

const hitRateText = computed(() => {
  const rate = Number(sched.consumer_hit_rate) || 0
  return `${(rate * 100).toFixed(1)}%`
})
const hitRateClass = computed(() => {
  const rate = Number(sched.consumer_hit_rate) || 0
  if (rate >= 0.5) return 'is-good'
  if (rate >= 0.2) return 'is-mid'
  return 'is-bad'
})

// 失败原因排行（按 count 排序，给出占比）
const failureRows = computed(() => {
  const reasons = sched.failure_reasons || {}
  const total = Object.values(reasons).reduce((a, b) => a + (Number(b) || 0), 0)
  if (!total) return []
  return Object.entries(reasons)
    .map(([reason, count]) => ({
      reason,
      count: Number(count) || 0,
      pct: Math.round((Number(count) / total) * 100),
      hot: (Number(count) / total) >= 0.2
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12)
})

const filteredWarm = computed(() => {
  const states = sched.current_warm_states || []
  if (!stateFilter.value) return states
  return states.filter(s => s.state === stateFilter.value)
})

const stateTagType = (state) => {
  if (state === 'ready') return 'success'
  if (state === 'stale') return 'warning'
  if (state === 'invalid') return 'danger'
  return 'info'
}

const fmtTime = (ts) => {
  if (!ts) return ''
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  const p = (v) => String(v).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

onMounted(() => {
  fetchStats()
  timer = window.setInterval(() => fetchStats(), 8000)
})
onUnmounted(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped lang="scss">
.warm-page {
  padding: 6px 0 30px;
}
.warm-shell {
  max-width: 1320px;
  margin: 0 auto;
}

.warm-hero-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.warm-hero-card {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 10px;
  padding: 14px 16px;
  background: var(--el-bg-color);
}
.warm-hero-card__label {
  font-size: 12px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 8px;
}
.warm-hero-card__value {
  font-size: 26px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: var(--el-color-primary);
  line-height: 1.1;
}
.warm-hero-card__value--sm {
  font-size: 18px;
}
.warm-hero-card__value.is-good { color: var(--el-color-success); }
.warm-hero-card__value.is-mid { color: var(--el-color-warning); }
.warm-hero-card__value.is-bad { color: var(--el-color-danger); }
.warm-hero-card__meta {
  margin-top: 8px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.empty-hint {
  padding: 18px;
  text-align: center;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}

.fail-rank {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.fail-rank__row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.fail-rank__bar-wrap {
  flex: 1;
  min-width: 0;
}
.fail-rank__reason {
  font-size: 12px;
  color: var(--el-text-color-primary);
  margin-bottom: 3px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.fail-rank__bar {
  height: 8px;
  border-radius: 4px;
  background: var(--el-fill-color-light);
  overflow: hidden;
}
.fail-rank__bar-inner {
  height: 100%;
  border-radius: 4px;
  background: var(--el-color-primary);
  transition: width 0.3s;
}
.fail-rank__bar-inner.is-hot {
  background: var(--el-color-danger);
}
.fail-rank__count {
  font-size: 12px;
  font-weight: 600;
  color: var(--el-text-color-primary);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

/* 窄屏表格横向滚动 */
.table-scroll {
  width: 100%;
  overflow-x: auto;
}
@media (max-width: 768px) {
  .warm-hero-card__value {
    font-size: 22px;
  }
}
</style>