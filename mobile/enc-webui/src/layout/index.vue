<template>
  <div :class="classObj" class="layout-wrapper">
    <div class="layout-wrapper__glow layout-wrapper__glow--left" />
    <div class="layout-wrapper__glow layout-wrapper__glow--right" />
    <!--left side-->
    <Sidebar v-if="settings.showLeftMenu" class="sidebar-container" />
    <!--right container-->
    <div class="main-container">
      <Navbar v-if="settings.showTopNavbar" />
      <TagsView v-if="settings.showTagsView" />
      <AppMain />
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import Sidebar from './sidebar/index.vue'
import AppMain from './app-main/index.vue'
import Navbar from './app-main/Navbar.vue'
import TagsView from './app-main/TagsView.vue'
import { useBasicStore } from '@/store/basic'
import { resizeHandler } from '@/hooks/use-layout'
const { sidebar, settings } = useBasicStore()
const classObj = computed(() => {
  return {
    closeSidebar: !sidebar.opened,
    hideSidebar: !settings.showLeftMenu
  }
})
resizeHandler()
</script>

<style lang="scss" scoped>
.layout-wrapper {
  position: relative;
  min-height: 100%;
  background: transparent;
}

.layout-wrapper__glow {
  position: fixed;
  inset: auto;
  width: 360px;
  height: 360px;
  border-radius: 50%;
  pointer-events: none;
  filter: blur(80px);
  opacity: 0.42;
  z-index: 0;
}

.layout-wrapper__glow--left {
  top: -120px;
  left: -120px;
  background: color-mix(in srgb, var(--el-color-primary) 32%, transparent);
}

.layout-wrapper__glow--right {
  top: 20%;
  right: -140px;
  background: color-mix(in srgb, var(--el-color-primary-dark-2) 28%, transparent);
}

.main-container {
  min-height: 100%;
  transition: margin-left var(--sideBar-switch-duration);
  margin-left: var(--side-bar-width);
  position: relative;
  z-index: 1;
}
.sidebar-container {
  transition: width var(--sideBar-switch-duration);
  width: var(--side-bar-width) !important;
  background: linear-gradient(180deg, var(--app-surface-strong), var(--app-surface));
  height: 100%;
  position: fixed;
  font-size: 0;
  top: 0;
  bottom: 0;
  left: 0;
  z-index: 1001;
  overflow: hidden;
  border-right: 1px solid var(--side-bar-border-right-color);
  box-shadow: 18px 0 48px rgba(40, 52, 80, 0.12);
}
.closeSidebar {
  .sidebar-container {
    width: 84px !important;
  }
  .main-container {
    margin-left: 84px !important;
  }
}
.hideSidebar {
  .sidebar-container {
    width: 0 !important;
  }
  .main-container {
    margin-left: 0;
  }
}
</style>
