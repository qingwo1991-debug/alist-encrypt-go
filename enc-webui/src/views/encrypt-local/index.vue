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
          <el-form-item label="算法">
            <el-radio-group v-model="folderForm.encType" size="small">
              <el-radio label="aesctr" border>AES-CTR</el-radio>
              <el-radio label="rc4" border>RC4</el-radio>
              <el-radio label="chacha20" border>ChaCha20</el-radio>
            </el-radio-group>
          </el-form-item>
          <div class="form-grid">
            <el-form-item label="密码">
              <el-input v-model="folderForm.password" placeholder="12341234" />
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
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { useConfigStore } from '@/store/config'
import { useBasicStore } from '@/store/basic'
import { usePageStore } from '@/store/pageStore'
import { encryptFileReq } from '@/api/user'

import { CirclePlus, Folder } from '@element-plus/icons-vue'
import { random } from 'lodash'

const labelPosition = ref('right')
const dialogFolderFormVisible = ref(false)
const activeName = ref('encode')

const basicStore = useBasicStore()
const { settings, userInfo } = basicStore

const { folderInfo, setFolderInfo } = usePageStore()

const { setLanguage } = useConfigStore()
const route = useRoute()
const changeLanguage = (langParam) => {
  setLanguage(langParam)
}

const folderForm = reactive({
  folderPath: folderInfo.folderPath,
  outPath: folderInfo.outPath,
  encType: 'aesctr',
  password: '123456', // 文件夹密码
  operation: 'enc',
  encName: false,
  encSuffix: ''
})

const alistConfigForm = reactive({})
const refSearchForm = ref()

const delPasswd = (index) => {
  alistConfigForm.passwdList.splice(index, 1)
}

const encryptFile = () => {
  setFolderInfo(Object.assign({}, folderForm))
  encryptFileReq(folderForm).then((res) => {
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
