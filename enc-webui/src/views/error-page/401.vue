<template>
  <div class="error-page">
    <div class="panel-card error-card">
      <div class="page-eyebrow">401</div>
      <div class="page-title">无权访问</div>
      <div class="page-subtitle">当前账号没有访问该页面的权限。你可以返回上一页，或回到首页重新选择入口。</div>
      <div class="page-actions">
        <el-button @click="back">返回上一页</el-button>
        <router-link to="/dashboard">
          <el-button type="primary">回到首页</el-button>
        </router-link>
      </div>
    </div>
  </div>
</template>

<script setup>
const route = useRoute()
const router = useRouter()
const back = () => {
  if (route.query.noGoBack) {
    router.push({ path: '/dashboard' })
  } else {
    router.go(-1)
  }
}
</script>

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
