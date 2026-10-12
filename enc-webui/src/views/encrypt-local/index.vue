<template>
  <div class="encrypt-local-page scroll-y">
    <div class="admin-page encrypt-local-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Local Encryptor</div>
          <div class="page-title">本地加解密</div>
          <div class="page-subtitle">
            适合在运行 `encrypt.exe` 或本地代理程序的主机上，对文件夹内容进行批量加密或解密，并保持和后台控制台统一的输入节奏。
          </div>
        </div>
      </section>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">任务配置</div>
            <div class="panel-card__subtitle">选择操作类型、算法、密码和输入输出目录后即可执行。</div>
          </div>
        </div>

        <el-form ref="refSearchForm" :label-position="labelPosition" label-width="75px" :model="folderForm">
          <el-form-item label="操作">
            <el-radio-group v-model="folderForm.operation" size="small">
              <el-radio label="enc" border>加密</el-radio>
              <el-radio label="dec" border>解密</el-radio>
            </el-radio-group>
          </el-form-item>
          <template v-if="folderForm.operation === 'enc'">
            <el-form-item label="格式">
              <el-select v-model="folderForm.v2">
                <el-option :value="false" label="V3 AES-GCM（默认）" />
                <el-option :value="true" label="V2（旧版兼容）" />
              </el-select>
            </el-form-item>
            <el-form-item v-if="!folderForm.v2" label="分块">
              <el-select v-model="folderForm.v3ChunkSize">
                <el-option :value="0" label="兼容默认 · 16 MiB" />
                <el-option :value="1048576" label="播放优化 · 1 MiB（可选）" />
              </el-select>
              <div class="helper-inline">仅影响新加密文件；1 MiB 减少播放与拖动时的单块读取量。</div>
            </el-form-item>
          </template>
          <el-form-item :label="folderForm.operation === 'enc' && !folderForm.v2 ? '文件名算法' : '算法'">
            <el-radio-group v-model="folderForm.encType" size="small">
              <el-radio label="aesctr" border>AES-CTR</el-radio>
              <el-radio label="rc4md5" border>RC4-MD5</el-radio>
              <el-radio label="chacha20" border>ChaCha20</el-radio>
            </el-radio-group>
          </el-form-item>
          <div class="form-grid">
            <el-form-item label="密码">
              <el-input v-model="folderForm.password" type="password" show-password autocomplete="new-password" placeholder="请输入加解密密码" />
            </el-form-item>
            <el-form-item label="后缀">
              <el-input v-model="folderForm.encSuffix" placeholder=".bin / 默认原文件名后缀" />
            </el-form-item>
            <el-form-item label="文件夹">
              <el-input v-model="folderForm.folderPath" placeholder="/home/my-video" />
            </el-form-item>
            <el-form-item label="输出">
              <el-input v-model="folderForm.outPath" placeholder="/home/outPath" />
            </el-form-item>
          </div>
          <el-form-item label="文件名">
            <span class="helper-inline">加密</span>
            <el-switch v-model="folderForm.encName" class="ml-2" />
          </el-form-item>
          <div class="page-actions">
            <el-button v-if="folderForm.operation == 'enc'" type="primary" @click="encryptFile">加密</el-button>
            <el-button v-if="folderForm.operation == 'dec'" type="success" @click="encryptFile">解密</el-button>
          </div>
        </el-form>
      </section>
    </div>
  </div>
</template>
<script setup>
import { reactive, ref } from 'vue'
import { usePageStore } from '@/store/pageStore'
import { encryptFileReq } from '@/api/user'
const labelPosition = ref('right')

const { folderInfo, setFolderInfo } = usePageStore()

const folderForm = reactive({
  folderPath: folderInfo.folderPath,
  outPath: folderInfo.outPath,
  encType: 'aesctr',
  password: '',
  operation: 'enc',
  encName: false,
  encSuffix: '',
  v2: false,
  v3ChunkSize: 0
})

const refSearchForm = ref()

const encryptFile = () => {
  if (!String(folderForm.password ?? '').trim()) {
    ElMessage.error('请输入加解密密码')
    return
  }

  setFolderInfo({ folderPath: folderForm.folderPath, outPath: folderForm.outPath })
  // Chunk geometry belongs to newly written V3 files, not global settings
  // or the decoding of existing containers. Never send it for V2/decryption.
  const { v2, v3ChunkSize, ...fields } = folderForm
  const request = folderForm.operation === 'enc'
    ? { ...fields, v2, ...(!v2 ? { v3ChunkSize } : {}) }
    : fields
  return encryptFileReq(request).then((res) => {
    ElMessage.success(res.msg)
  })
}
</script>

<style scoped lang="scss">
.encrypt-local-page {
  padding: 6px 0 30px;
}

.encrypt-local-shell {
  max-width: 1320px;
  margin: 0 auto;
}

.helper-inline {
  margin-right: 12px;
  color: var(--el-text-color-secondary);
}
</style>
