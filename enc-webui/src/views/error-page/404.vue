<template>
  <div class="error-page">
    <div class="panel-card error-card">
      <div class="page-eyebrow">404</div>
      <div class="page-title">页面未找到</div>
      <div class="page-subtitle">请求的地址不存在，或该入口已经被移除。请返回首页继续操作。</div>
      <div class="page-actions">
        <router-link to="/dashboard">
          <el-button type="primary">回到首页</el-button>
        </router-link>
      </div>
    </div>
  </div>
</template>

<style scoped lang="scss">
.error-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}

.error-card {
  width: min(560px, 100%);
  text-align: center;
}

.page-actions {
  justify-content: center;
  margin-top: 20px;
}
</style>
