<template>
  <div id="Sidebar" class="reset-menu-style sidebar-shell">
    <!--logo-->
    <Logo v-if="settings.sidebarLogo" :collapse="!sidebar.opened" />
    <!--router menu-->
    <el-scrollbar class="sidebar-shell__scroll">
      <el-menu
        class="el-menu-vertical sidebar-shell__menu"
        :collapse="!sidebar.opened"
        :default-active="activeMenu"
        :collapse-transition="false"
        mode="vertical"
      >
        <sidebar-item v-for="route in allRoutes" :key="route.path" :item="route" :base-path="route.path" />
      </el-menu>
    </el-scrollbar>
    <div class="sidebar-profile" :class="{ 'sidebar-profile--collapse': !sidebar.opened }">
      <div class="sidebar-profile__avatar">{{ userInitial }}</div>
      <div v-if="sidebar.opened" class="sidebar-profile__content">
        <div class="sidebar-profile__name">{{ userInfo.username || 'admin' }}</div>
        <div class="sidebar-profile__version">Runtime {{ userInfo.version }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia/dist/pinia'
import { useRoute } from 'vue-router'
import Logo from './Logo.vue'
import SidebarItem from './SidebarItem.vue'
import { useBasicStore } from '@/store/basic'
const { settings, allRoutes, sidebar, userInfo } = storeToRefs(useBasicStore())
const routeInstance = useRoute()
const userInitial = computed(() => (userInfo.value.username || 'A').slice(0, 1).toUpperCase())
const activeMenu = computed(() => {
  const { meta, path } = routeInstance
  // if set path, the sidebar will highlight the path you set
  if (meta.activeMenu) {
    return meta.activeMenu
  }
  return path
})
</script>
<style lang="scss">
//fix open the item style issue
.sidebar-shell {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.sidebar-shell__scroll {
  flex: 1;
}

.el-menu-vertical {
  width: var(--side-bar-width);
}

.sidebar-shell__menu {
  padding: 18px 14px 12px;
}

.reset-menu-style {
  border-right: 1px solid var(--side-bar-border-right-color);
}

.sidebar-profile {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 14px;
  padding: 14px;
  border-radius: var(--app-radius-lg);
  border: 1px solid var(--app-border-color);
  background: linear-gradient(180deg, var(--app-surface-soft), var(--app-surface));
  box-shadow: var(--app-shadow-md);
}

.sidebar-profile--collapse {
  justify-content: center;
  padding: 10px;
}

.sidebar-profile__avatar {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  border-radius: 14px;
  background: linear-gradient(180deg, var(--el-color-primary-light-3) 0%, var(--el-color-primary) 100%);
  color: #fff;
  font-size: 16px;
  font-weight: 700;
}

.sidebar-profile__name {
  font-size: 14px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.sidebar-profile__version {
  margin-top: 5px;
  font-size: 11px;
  color: var(--el-text-color-secondary);
}
</style>
