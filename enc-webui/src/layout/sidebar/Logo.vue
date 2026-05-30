<template>
  <div class="sidebar-logo-container" :class="{ collapse: collapse }">
    <transition name="sidebar-logo-fade">
      <!--  折叠显示   -->
      <router-link v-if="collapse" class="sidebar-logo-link" to="/">
        <svg-icon v-if="logo" :icon-class="logo" class="sidebar-logo" />
        <h1 v-else class="sidebar-title">{{ title }}</h1>
      </router-link>
      <!--  正常显示   -->
      <router-link v-else class="sidebar-logo-link" to="/">
        <svg-icon v-if="logo" :icon-class="logo" class="sidebar-logo" />
        <h1 class="sidebar-title">{{ title }}</h1>
      </router-link>
      <!-- <div class="sidebar-title"> 333</div> -->
    </transition>
  </div>
</template>

<script setup lang="ts">
import { reactive, toRefs } from 'vue'
import { useBasicStore } from '@/store/basic'
import SvgIcon from '@/icons/SvgIcon.vue'
const { settings } = useBasicStore()
defineProps({
  //是否折叠
  collapse: {
    type: Boolean,
    required: true
  }
})
const state = reactive({
  title: settings.title,
  //src/icons/common/sidebar-logo.svg
  logo: 'sidebar-logo'
})
//export to page for use
const { title, logo } = toRefs(state)
</script>

<style lang="scss">
//vue3.0 过度效果更改  enter-> enter-from   leave-> leave-from
.sidebar-logo-container {
  position: relative;
  width: 100%;
  height: 84px;
  line-height: 84px;
  background: var(--sidebar-logo-background);
  padding: 18px 18px 10px;
  text-align: left;
  overflow: hidden;
  & .sidebar-logo-link {
    display: flex;
    align-items: center;
    height: 100%;
    width: 100%;
    padding: 12px 14px;
    border-radius: var(--app-radius-lg);
    border: 1px solid var(--app-border-color);
    background: linear-gradient(180deg, var(--app-surface-soft), var(--app-surface));
    box-shadow: var(--app-shadow-md);
    & .sidebar-logo {
      fill: currentColor;
      color: var(--sidebar-logo-color);
      width: var(--sidebar-logo-width);
      height: var(--sidebar-logo-height);
      vertical-align: middle;
      margin-right: 14px;
    }
    & .sidebar-title {
      display: inline-block;
      margin: 0;
      color: var(--sidebar-logo-title-color);
      font-weight: 700;
      line-height: 1.2;
      font-size: 15px;
      font-family: Inter, 'Segoe UI', 'PingFang SC', sans-serif;
      letter-spacing: 0.04em;
      vertical-align: middle;
    }
  }
  &.collapse {
    .sidebar-logo {
      margin-right: 0;
    }
  }
}
</style>
