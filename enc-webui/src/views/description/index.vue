<template>
  <div class="description-page scroll-y">
    <div class="admin-page description-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Project Overview</div>
          <div class="page-title">alist-encrypt</div>
          <div class="page-subtitle">
            这个项目为 Alist 提供透明代理、WebDAV 加解密、在线播放与预热能力。新版说明页保留原有信息，但用统一卡片层级提升可读性。
          </div>
        </div>
      </section>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">核心定位</div>
            <div class="panel-card__subtitle">结合 Alist 与 WebDAV，在不改变日常使用方式的前提下提供透明加解密和在线播放能力。</div>
          </div>
        </div>
        <div class="info-grid">
          <div class="info-card">
            <div class="hero-pill__label">场景</div>
            <div class="hero-pill__meta">网盘敏感资源保护、视频在线播放、图片查看、透明上传下载。</div>
          </div>
          <div class="info-card">
            <div class="hero-pill__label">能力</div>
            <div class="hero-pill__meta">网页代理、WebDAV 加解密、播放器跳转、配置化密码规则。</div>
          </div>
          <div class="info-card">
            <div class="hero-pill__label">现状</div>
            <div class="hero-pill__meta">Go 版本后台已具备更稳健的并发和部署形态，UI 同步升级到统一控制台语言。</div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped lang="scss">
.description-page {
  padding: 6px 0 30px;
}

.description-shell {
  max-width: 1320px;
  margin: 0 auto;
}
</style>
