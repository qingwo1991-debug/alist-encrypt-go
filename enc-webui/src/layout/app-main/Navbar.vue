<template>
  <div class="navbar reset-el-dropdown">
    <div class="navbar__left">
      <!--  切换sidebar按钮  -->
      <hamburger v-if="settings.showHamburger" :is-active="sidebar.opened" class="hamburger-container" @toggleClick="toggleSideBar" />
      <!--  面包屑导航  -->
      <breadcrumb class="breadcrumb-container" />
    </div>
    <div class="navbar__center">
      <div class="navbar__brand">alist-encrypt-go</div>
      <div class="navbar__meta">Go runtime · proxy control plane</div>
    </div>
    <div v-if="settings.ShowDropDown" class="right-menu">
      <el-dropdown trigger="click" size="medium">
        <div class="avatar-wrapper">
          <div class="avatar-wrapper__identity">
            <div class="avatar-wrapper__name">{{ userInfo.username || 'admin' }}</div>
            <div class="avatar-wrapper__version">v{{ userInfo.version }}</div>
          </div>
          <div class="user-avatar">{{ avatarInitial }}</div>
          <CaretBottom class="avatar-wrapper__caret" />
        </div>
        <template #dropdown>
          <el-dropdown-menu>
            <router-link to="/">
              <el-dropdown-item>{{ langTitle('Home') }}</el-dropdown-item>
            </router-link>
            <a target="_blank" href="https://github.com/jzfai/vue3-admin-template">
              <el-dropdown-item>{{ langTitle('Github') }}</el-dropdown-item>
            </a>
            <!--<el-dropdown-item>修改密码</el-dropdown-item>-->
            <el-dropdown-item divided @click="loginOut">{{ langTitle('login out') }}</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick } from 'vue'
import { CaretBottom } from '@element-plus/icons-vue'
import { useRouter } from 'vue-router'
import Breadcrumb from './Breadcrumb.vue'
import Hamburger from './Hamburger.vue'
import { resetState } from '@/hooks/use-permission'
import { elMessage } from '@/hooks/use-element'
import { useBasicStore } from '@/store/basic'
import { langTitle } from '@/hooks/use-common'

const basicStore = useBasicStore()
const { settings, sidebar, setToggleSideBar, userInfo } = basicStore
const avatarInitial = computed(() => (userInfo.username || 'A').slice(0, 1).toUpperCase())
const toggleSideBar = () => {
  setToggleSideBar()
}
//退出登录
const router = useRouter()
const loginOut = () => {
  elMessage('退出登录成功')
  router.push(`/login?redirect=/`)
  nextTick(() => {
    resetState()
  })
}
</script>

<style lang="scss" scoped>
.navbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 18px;
  height: calc(var(--nav-bar-height) - 10px);
  margin: 14px 22px 0;
  padding: 0 20px;
  border-radius: var(--app-radius-xl);
  border: 1px solid var(--app-border-color);
  background: var(--nav-bar-background);
  box-shadow: var(--app-shadow-md);
  backdrop-filter: blur(20px);
  position: sticky;
  top: 12px;
  z-index: 5;
}

.navbar__left {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.navbar__center {
  justify-self: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 5px;
  min-width: 0;
}

.navbar__brand {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--el-text-color-primary);
}

.navbar__meta {
  font-size: 11px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--el-text-color-secondary);
}

.avatar-wrapper {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px 10px 16px;
  border-radius: var(--app-radius-md);
  border: 1px solid var(--app-border-color);
  background: rgba(255, 255, 255, 0.03);
  box-shadow: var(--app-shadow-md);
  position: relative;
  cursor: pointer;
}

.avatar-wrapper__identity {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.avatar-wrapper__name {
  font-size: 14px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.avatar-wrapper__version {
  font-size: 11px;
  color: var(--el-text-color-secondary);
}

.user-avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  border-radius: 14px;
  background: linear-gradient(180deg, #6a9aff 0%, #4f81f6 100%);
  color: #f6f8ff;
  font-size: 16px;
  font-weight: 700;
  box-shadow: var(--app-glow-primary);
}

.right-menu {
  justify-self: end;
}

.avatar-wrapper__caret {
  width: 1em;
  height: 1em;
  color: var(--el-text-color-secondary);
}

@media (max-width: 1100px) {
  .navbar {
    grid-template-columns: minmax(0, 1fr) auto;
  }

  .navbar__center {
    display: none;
  }
}

@media (max-width: 768px) {
  .navbar {
    margin: 12px 14px 0;
    padding: 0 14px;
  }

  .avatar-wrapper {
    padding-left: 12px;
  }

  .avatar-wrapper__identity {
    display: none;
  }
}
</style>
