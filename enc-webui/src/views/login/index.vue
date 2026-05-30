<!--suppress ALL -->
<template>
  <div class="login-container">
    <div class="login-container__glow login-container__glow--left" />
    <div class="login-container__glow login-container__glow--right" />
    <div class="login-panel">
      <div class="page-eyebrow">Secure Gateway</div>
      <h3 class="login-panel__title">{{ settings.title }}</h3>
      <p class="login-panel__subtitle">统一的深色控制台入口，为 Go 代理服务提供更稳健清晰的登录体验。</p>

      <el-form ref="refLoginForm" class="login-form" :model="subForm" :rules="formRules">
        <el-form-item prop="username" :rules="formRules.isNotNull('usename不能为空')">
          <div class="login-field">
            <span class="svg-container">
              <svg-icon icon-class="user" />
            </span>
            <el-input v-model="subForm.username" placeholder="用户名(admin)" />
          </div>
        </el-form-item>
        <el-form-item prop="password" :rules="formRules.isNotNull('密码不能为空')">
          <div class="login-field">
            <span class="svg-container">
              <svg-icon icon-class="password" />
            </span>
            <el-input
              :key="passwordType"
              ref="refPassword"
              v-model="subForm.password"
              :type="passwordType"
              name="password"
              placeholder="password"
              @keyup.enter="handleLogin"
            />
            <span class="show-pwd" @click="showPwd">
              <svg-icon :icon-class="passwordType === 'password' ? 'eye' : 'eye-open'" />
            </span>
          </div>
        </el-form-item>
        <div class="tip-message">{{ tipMessage }}</div>
        <el-button :loading="subLoading" type="primary" class="login-btn" size="default" @click.prevent="handleLogin">
          Login
        </el-button>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { nextTick, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useBasicStore } from '@/store/basic'
import { elMessage, useElement } from '@/hooks/use-element'
import { loginReq } from '@/api/user'

const { settings } = useBasicStore()
const formRules = useElement().formRules
const subForm = reactive({
  username: 'admin',
  password: ''
})
const state = reactive({
  otherQuery: {},
  redirect: undefined
})
const route = useRoute()
const getOtherQuery = (query) => {
  return Object.keys(query).reduce((acc, cur) => {
    if (cur !== 'redirect') {
      acc[cur] = query[cur]
    }
    return acc
  }, {})
}
watch(
  () => route.query,
  (query) => {
    if (query) {
      state.redirect = query.redirect
      state.otherQuery = getOtherQuery(query)
    }
  },
  { immediate: true }
)

const subLoading = ref(false)
const tipMessage = ref('')
const refLoginForm = ref(null)
const handleLogin = () => {
  refLoginForm.value?.validate((valid) => {
    subLoading.value = true
    if (valid) loginFunc()
  })
}
const router = useRouter()
const basicStore = useBasicStore()

const loginFunc = () => {
  loginReq(subForm)
    .then(({ data }) => {
      elMessage('登录成功')
      basicStore.setToken(data?.jwtToken)
      router.push('/')
    })
    .catch((err) => {
      tipMessage.value = err?.msg
    })
    .finally(() => {
      subLoading.value = false
    })
}

const passwordType = ref('password')
const refPassword = ref(null)
const showPwd = () => {
  passwordType.value = passwordType.value === 'password' ? '' : 'password'
  nextTick(() => {
    refPassword.value.focus()
  })
}
</script>

<style lang="scss" scoped>
.login-container {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  overflow: hidden;
}

.login-container__glow {
  position: absolute;
  width: 420px;
  height: 420px;
  border-radius: 50%;
  filter: blur(90px);
  opacity: 0.32;
}

.login-container__glow--left {
  top: -120px;
  left: -120px;
  background: rgba(91, 140, 255, 0.32);
}

.login-container__glow--right {
  right: -100px;
  bottom: -140px;
  background: rgba(56, 88, 186, 0.28);
}

.login-panel {
  position: relative;
  z-index: 1;
  width: min(460px, 100%);
  padding: 32px;
  border-radius: 28px;
  border: 1px solid rgba(145, 167, 255, 0.16);
  background: linear-gradient(180deg, rgba(27, 35, 58, 0.86), rgba(17, 23, 39, 0.94));
  box-shadow: var(--app-shadow-lg);
  backdrop-filter: blur(24px);
}

.login-panel__title {
  margin-top: 12px;
  font-size: 30px;
  line-height: 1.1;
  font-weight: 700;
  color: var(--el-text-color-primary);
}

.login-panel__subtitle {
  margin-top: 12px;
  margin-bottom: 28px;
  line-height: 1.7;
  color: var(--el-text-color-regular);
}

.login-field {
  display: flex;
  align-items: center;
  width: 100%;
}

.svg-container {
  width: 32px;
  color: var(--el-text-color-secondary);
}

.tip-message {
  min-height: 24px;
  margin-top: -6px;
  margin-bottom: 8px;
  font-size: 12px;
  color: #ff6f91;
}

.login-btn {
  width: 100%;
}

.show-pwd {
  width: 40px;
  text-align: center;
  color: var(--el-text-color-secondary);
  cursor: pointer;
}
</style>

<style lang="scss">
.login-container {
  .el-form-item {
    margin-bottom: 18px;
  }

  .el-form-item__content {
    display: block;
  }

  .el-input__wrapper {
    box-shadow: none;
    background: transparent;
  }
}
</style>
