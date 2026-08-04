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
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { getStatsReq } from '@/api/user'

const buildInfo = reactive({})
const runtime = reactive({
  uptime: '',
  sched: {},
  stream: {},
  cache: {}
})
const refreshing = ref(false)
let timer = null

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
  timer = window.setInterval(() => loadAll(), 10000)
})
onUnmounted(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<style scoped lang="scss">
.system-info-page {
  padding: 6px 0 30px;
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
