<template>
  <div class="online-encrypt-page scroll-y">
    <div class="admin-page online-encrypt-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Online Encryption</div>
          <div class="page-title">在线加密</div>
          <div class="page-subtitle">
            为在线加密和解密能力预留统一的控制页面，让后续功能扩展和主后台保持同样的结构、节奏和视觉标准。
          </div>
        </div>
      </section>

      <div class="two-column-grid">
        <section class="panel-card">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">能力说明</div>
              <div class="panel-card__subtitle">文件可以在线加密与解密，界面会继续沿用服务配置页的卡片和表单样式。</div>
            </div>
          </div>
          <div class="stack-grid">
            <div class="info-card">
              <div class="hero-pill__label">Current State</div>
              <div class="hero-pill__value">Planned</div>
              <div class="hero-pill__meta">当前为统一视觉占位页，后续业务能力可直接填充进来。</div>
            </div>
          </div>
        </section>

        <section class="panel-card panel-card--soft">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">设计目标</div>
              <div class="panel-card__subtitle">保证配置页、工具页和状态页之间没有割裂感。</div>
            </div>
          </div>
          <div class="stack-grid muted-text">
            <div>统一蓝色主色、圆角和阴影。</div>
            <div>保留深色背景和轻玻璃质感。</div>
            <div>后续接入表单与运行状态时无需重做页面骨架。</div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { storeToRefs } from 'pinia/dist/pinia'
import { useBasicStore } from '@/store/basic'
const { settings } = storeToRefs(useBasicStore())
</script>

<style scoped lang="scss">
.online-encrypt-page {
  padding: 6px 0 30px;
}

.online-encrypt-shell {
  max-width: 1320px;
  margin: 0 auto;
}
</style>
