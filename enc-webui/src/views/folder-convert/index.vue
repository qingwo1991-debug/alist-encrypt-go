<template>
  <div class="folder-convert-page scroll-y">
    <div class="admin-page folder-convert-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Transfer Pipeline</div>
          <div class="page-title">文件转存</div>
          <div class="page-subtitle">
            文件转存会用于把任意网盘文件转到加密目录中。当前页面保留上传入口，并用统一的卡片结构提示适用范围和风险。
          </div>
        </div>
      </section>

      <div class="two-column-grid">
        <section class="panel-card">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">使用建议</div>
              <div class="panel-card__subtitle">建议 1G 内文件直接转存，大文件优先本地加密后由云盘客户端上传。</div>
            </div>
          </div>
          <div class="stack-grid muted-text">
            <div>文件转存适合小体积文件快速进入加密目录。</div>
            <div>大文件场景优先使用本地工具，降低中途失败风险。</div>
          </div>
        </section>

        <section class="panel-card panel-card--soft">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">上传入口</div>
              <div class="panel-card__subtitle">保留现有 `encryptFile` 上传地址，不变更后端行为。</div>
            </div>
          </div>
          <el-upload
            v-model:file-list="fileList"
            class="upload-demo"
            action="/enc-api/encryptFile"
            multiple
            :on-preview="handlePreview"
            :on-remove="handleRemove"
            :before-remove="beforeRemove"
            :limit="3"
            :on-exceed="handleExceed"
          >
            <el-button type="primary">选择文件</el-button>
            <template #tip>
              <div class="helper-text">功能仍在完善中，上传入口先统一到新版页面壳里。</div>
            </template>
          </el-upload>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
const fileList = ref([])
const handlePreview = () => {}
const handleRemove = () => {}
const beforeRemove = () => true
const handleExceed = () => {}
</script>

<style scoped lang="scss">
.folder-convert-page {
  padding: 6px 0 30px;
}

.folder-convert-shell {
  max-width: 1320px;
  margin: 0 auto;
}
</style>
