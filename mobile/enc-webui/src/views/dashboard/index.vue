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
              <div class="panel-card__subtitle">围绕 Go 版本的稳定性和维护效率来表达工程感。</div>
            </div>
          </div>

          <div class="stats-grid">
            <div class="stats-card">
              <div class="stats-card__label">Engine</div>
              <div class="stats-card__value">Go</div>
              <div class="stats-card__meta">更稳定的代理与并发处理模型。</div>
            </div>
            <div class="stats-card">
              <div class="stats-card__label">Panel</div>
              <div class="stats-card__value">Unified</div>
              <div class="stats-card__meta">服务配置、WebDAV 和在线加密使用同一套视觉语言。</div>
            </div>
          </div>
        </section>
      </div>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">账号设置</div>
            <div class="panel-card__subtitle">修改密码后即可生效，界面布局与全站保持一致。</div>
          </div>
        </div>

        <el-form ref="refSearchForm" :label-position="labelPosition" label-width="88px" :model="userForm">
          <div class="form-grid">
            <el-form-item prop="username" label="用户名">
              <el-input v-model="userForm.username" disabled="true" placeholder="username" />
            </el-form-item>
            <el-form-item prop="password" label="原密码">
              <el-input v-model="userForm.password" type="password" placeholder="password" />
            </el-form-item>
            <el-form-item prop="newpassword" label="新密码">
              <el-input v-model="userForm.newpassword" type="password" placeholder="password" />
            </el-form-item>
          </div>
          <div class="page-actions">
            <el-button type="primary" @click="updatePasswd">修改密码</el-button>
          </div>
        </el-form>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { storeToRefs } from 'pinia'
import { useConfigStore } from '@/store/config'
import { useBasicStore } from '@/store/basic'
import { upatePasswordReq } from '@/api/user'

const labelPosition = ref('right')

const basicStore = useBasicStore()
const { userInfo } = basicStore

const configStore = useConfigStore()
const { theme, language } = storeToRefs(configStore)
const { setTheme, setSize, setLanguage } = configStore
setSize('default')

const changeLanguage = (langParam) => {
  setLanguage(langParam)
}

const userForm = reactive({
  username: '',
  password: '',
  newpassword: ''
})
const refSearchForm = ref()
userForm.username = userInfo.username

const updatePasswd = () => {
  upatePasswordReq(userForm)
}
</script>

<style scoped lang="scss">
.dashboard-page {
  padding: 6px 0 30px;
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
