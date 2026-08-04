<template>
  <div class="dashboard-page scroll-y">
    <div class="admin-page dashboard-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Control Center</div>
          <div class="page-title">管理后台</div>
          <div class="page-subtitle">
            统一展示主题、语言和账户设置入口，让整个代理服务从首页开始就具备更稳健的控制面板观感。
          </div>
          <div class="hero-pills">
            <div class="hero-pill">
              <div class="hero-pill__label">当前主题</div>
              <div class="hero-pill__value">{{ theme }}</div>
              <div class="hero-pill__meta">默认深色模式，支持快速切换。</div>
            </div>
            <div class="hero-pill">
              <div class="hero-pill__label">当前语言</div>
              <div class="hero-pill__value">{{ language }}</div>
              <div class="hero-pill__meta">界面文本即时生效。</div>
            </div>
            <div class="hero-pill">
              <div class="hero-pill__label">当前用户</div>
              <div class="hero-pill__value">{{ userInfo.username || 'admin' }}</div>
              <div class="hero-pill__meta">版本 {{ userInfo.version }}</div>
            </div>
          </div>
        </div>
      </section>

      <div class="two-column-grid">
        <section class="panel-card">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">界面偏好</div>
              <div class="panel-card__subtitle">统一的主题和语言切换入口，按钮样式与全站保持一致。</div>
            </div>
          </div>

          <div class="stack-grid">
            <div>
              <div class="settings-label">主题</div>
              <div class="page-actions">
                <el-button :type="theme === 'lighting-theme' ? 'primary' : 'default'" @click="setTheme('lighting-theme')">light</el-button>
                <el-button :type="theme === 'dark' ? 'primary' : 'default'" @click="setTheme('dark')">dark</el-button>
              </div>
            </div>
            <div>
              <div class="settings-label">语言</div>
              <div class="page-actions">
                <el-button :type="language === 'en' ? 'primary' : 'default'" @click="changeLanguage('en')">en</el-button>
                <el-button :type="language === 'zh' ? 'primary' : 'default'" @click="changeLanguage('zh')">zh</el-button>
              </div>
            </div>
          </div>
        </section>

        <section class="panel-card panel-card--soft">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">运行摘要</div>
              <div class="panel-card__subtitle">解密流、预热状态与真实命中情况，每 8 秒自动刷新。最后更新 {{ runtime.updatedAt || '-' }}</div>
            </div>
            <el-button link type="primary" :loading="false" @click="fetchRuntimeStats">刷新</el-button>
          </div>

          <div class="stats-grid">
            <div class="stats-card">
              <div class="stats-card__label">解密流负载</div>
              <div class="stats-card__value">{{ runtime.activeStreams }}<span class="stats-card__unit">/{{ runtime.maxStreams }}</span></div>
              <div class="stats-card__meta">当前 {{ streamLoad }}%，累计拒绝 {{ runtime.rejectedStreams }}</div>
            </div>
            <div class="stats-card">
              <div class="stats-card__label">预热状态</div>
              <div class="stats-card__value">{{ runtime.warmReady }}<span class="stats-card__unit"> ready</span></div>
              <div class="stats-card__meta">过期 {{ runtime.warmStale }} · 失效 {{ runtime.warmInvalid }}</div>
            </div>
            <div class="stats-card">
              <div class="stats-card__label">真实命中</div>
              <div class="stats-card__value">{{ runtime.consumerHitTotal }}</div>
              <div class="stats-card__meta">命中率 {{ hitRateText }}（warm 成功 {{ runtime.filesSucceeded }}）</div>
            </div>
            <div class="stats-card">
              <div class="stats-card__label">预取队列</div>
              <div class="stats-card__value">{{ runtime.queueLen }}</div>
              <div class="stats-card__meta">待处理任务数</div>
            </div>
          </div>
        </section>
      </div>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">账号设置</div>
            <div class="panel-card__subtitle">用户名和密码修改逻辑保持不变，只升级输入布局和按钮层级。</div>
          </div>
        </div>

        <el-form ref="refSearchForm" :label-position="labelPosition" label-width="88px" :model="userForm">
          <div class="form-grid">
            <el-form-item prop="username" label="用户名">
              <el-input v-model="userForm.username" placeholder="username" />
            </el-form-item>
            <el-form-item prop="password" label="原密码">
              <el-input v-model="userForm.password" type="password" placeholder="password" />
            </el-form-item>
            <el-form-item prop="newpassword" label="新密码">
              <el-input v-model="userForm.newpassword" type="password" placeholder="password" />
            </el-form-item>
          </div>
          <div class="page-actions">
            <el-button type="primary" @click="updateUsername">修改用户名</el-button>
            <el-button type="warning" @click="updatePasswd">修改密码</el-button>
          </div>
        </el-form>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useConfigStore } from '@/store/config'
import { useBasicStore } from '@/store/basic'
import { upatePasswordReq, updateUsernameReq, getStatsReq } from '@/api/user'
import { ElMessage } from 'element-plus'

const labelPosition = ref('right')
const router = useRouter()

const basicStore = useBasicStore()
const { userInfo } = basicStore

const { setTheme, theme, setSize, language, setLanguage } = useConfigStore()
setSize('default')

const changeLanguage = (langParam) => {
  setLanguage(langParam)
}

const userForm = reactive({
  username: '',
  originalUsername: '',
  password: '',
  newpassword: ''
})
const refSearchForm = ref()
userForm.username = userInfo.username
userForm.originalUsername = userInfo.username

// ---- live runtime summary ----
const runtime = reactive({
  activeStreams: 0,
  maxStreams: 0,
  rejectedStreams: 0,
  warmReady: 0,
  warmStale: 0,
  warmInvalid: 0,
  consumerHitTotal: 0,
  consumerHitRate: 0,
  filesSucceeded: 0,
  queueLen: 0,
  updatedAt: ''
})
let statsTimer = null

const hitRateText = computed(() => {
  const rate = Number(runtime.consumerHitRate) || 0
  return `${(rate * 100).toFixed(1)}%`
})

const streamLoad = computed(() => {
  if (!runtime.maxStreams) return 0
  return Math.min(100, Math.round((runtime.activeStreams / runtime.maxStreams) * 100))
})

const fetchRuntimeStats = async () => {
  try {
    const res = await getStatsReq({ reqLoading: false })
    const data = res?.data || {}
    const sched = data.probe_scheduler || {}
    const stream = data.stream || {}
    const limiter = stream.limit || {}
    runtime.activeStreams = limiter.active_streams ?? 0
    runtime.maxStreams = limiter.max_active ?? 32
    runtime.rejectedStreams = limiter.rejected_streams ?? 0
    runtime.warmReady = sched.warm_state_counts?.warm_ready ?? 0
    runtime.warmStale = sched.warm_state_counts?.warm_stale ?? 0
    runtime.warmInvalid = sched.warm_state_counts?.warm_invalid ?? 0
    runtime.consumerHitTotal = sched.consumer_hit_total ?? 0
    runtime.consumerHitRate = sched.consumer_hit_rate ?? 0
    runtime.filesSucceeded = sched.files_succeeded_total ?? 0
    runtime.queueLen = sched.queue_len ?? 0
    runtime.updatedAt = new Date().toLocaleTimeString()
  } catch {
    /* dashboard stays silent on stats failure */
  }
}

onMounted(() => {
  fetchRuntimeStats()
  statsTimer = window.setInterval(() => fetchRuntimeStats(), 8000)
})
onUnmounted(() => {
  if (statsTimer) window.clearInterval(statsTimer)
})

const updatePasswd = () => {
  if (!userForm.password) {
    ElMessage.error('请输入原密码')
    return
  }
  if (!userForm.newpassword) {
    ElMessage.error('请输入新密码')
    return
  }
  upatePasswordReq({
    username: userForm.originalUsername,
    password: userForm.password,
    newpassword: userForm.newpassword
  }).then(() => {
    ElMessage.success('密码修改成功，请重新登录')
    basicStore.setToken('')
    router.push('/login')
  }).catch((err) => {
    ElMessage.error(err?.msg || '修改失败')
  })
}

const updateUsername = () => {
  if (!userForm.password) {
    ElMessage.error('请输入密码以验证身份')
    return
  }
  if (!userForm.username || userForm.username.length < 3) {
    ElMessage.error('用户名至少需要3个字符')
    return
  }
  if (userForm.username === userForm.originalUsername) {
    ElMessage.warning('用户名未变更')
    return
  }
  updateUsernameReq({
    username: userForm.originalUsername,
    password: userForm.password,
    newusername: userForm.username
  }).then(() => {
    ElMessage.success('用户名修改成功，请重新登录')
    basicStore.setToken('')
    router.push('/login')
  }).catch((err) => {
    ElMessage.error(err?.msg || '修改失败')
  })
}
</script>

<style scoped lang="scss">
.dashboard-page {
  padding: 6px 0 30px;
}

.stats-card__unit {
  margin-left: 4px;
  font-size: 14px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
}

.dashboard-shell {
  max-width: 1320px;
  margin: 0 auto;
}

.settings-label {
  margin-bottom: 12px;
  font-size: 13px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
</style>
