<template>
  <div class="setting-alist-page scroll-y">
    <div class="setting-alist-shell">
      <div class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">Service Control</div>
          <div class="page-title">服务配置</div>
          <div class="page-subtitle">
            Alist 代理、密码规则和加解密能力统一收拢到一套控制面板里，保持配置清晰、操作路径稳定。
          </div>
          <div class="hero-pills">
            <div class="hero-pill">
              <div class="hero-pill__label">Proxy Endpoint</div>
              <div class="hero-pill__value">{{ alistConfigForm.serverHost || '未配置' }}</div>
              <div class="hero-pill__meta">端口 {{ alistConfigForm.serverPort || '-' }} · {{ alistConfigForm.https ? 'HTTPS' : 'HTTP' }}</div>
            </div>
            <div class="hero-pill">
              <div class="hero-pill__label">密码规则</div>
              <div class="hero-pill__value">{{ alistConfigForm.passwdList?.length || 0 }}</div>
              <div class="hero-pill__meta">多算法、多路径统一维护。</div>
            </div>
          </div>
        </div>
        <div class="page-actions">
          <el-button type="primary" @click="saveAlistConfig">保存服务配置</el-button>
        </div>
      </div>

      <el-form ref="refSearchForm" :label-position="labelPosition" label-width="92px" :model="alistConfigForm" class="setting-form panel-card panel-card--soft">
        <el-collapse v-model="expandedSections" class="setting-collapse">
          <el-collapse-item name="connection">
            <template #title>
              <div class="section-banner">基础连接</div>
            </template>
            <div class="section-body">
              <el-form-item label="服务器">
                <el-input v-model="alistConfigForm.serverHost" style="max-width: 280px" placeholder="192.168.1.100" />
                <span class="helper-text">alist 的 IP 或域名地址</span>
              </el-form-item>
              <el-form-item label="端口">
                <el-input v-model="alistConfigForm.serverPort" style="max-width: 280px" placeholder="5244" />
              </el-form-item>
              <el-form-item label="HTTPS">
                <el-switch v-model="alistConfigForm.https" class="ml-2" />
                <span class="helper-text">默认 HTTP</span>
              </el-form-item>
            </div>
          </el-collapse-item>

          <el-collapse-item name="password">
            <template #title>
              <div class="section-banner section-banner--accent">密码规则</div>
            </template>
            <div class="section-body">
              <el-form-item label="密码设置">
                <el-button type="success" @click="addPasswd">添加规则</el-button>
              </el-form-item>
              <div class="passwd-list">
                <div v-for="(item, index) in alistConfigForm.passwdList" :key="item.id" class="passwd-card">
                  <div class="passwd-card__header">
                    <strong>配置 {{ index + 1 }}</strong>
                    <el-button type="danger" :icon="Delete" circle @click="delPasswd(index)" />
                  </div>
                  <el-form-item label="算法">
                    <el-radio-group v-model="item.encType" size="small">
                      <el-radio label="aesctr" border>AES-CTR</el-radio>
                      <el-radio label="rc4" border>RC4</el-radio>
                      <el-radio label="chacha20" border>ChaCha20</el-radio>
                    </el-radio-group>
                    <span class="helper-inline">开启</span>
                    <el-switch v-model="item.enable" class="ml-2" />
                  </el-form-item>
                  <el-form-item label="密码">
                    <el-input v-model="item.password" style="max-width: 280px" placeholder="12341234" />
                  </el-form-item>
                  <el-form-item label="文件名">
                    <span class="helper-inline">加密</span>
                    <el-switch v-model="item.encName" class="ml-2" style="margin-right: 10px" />
                    <span class="helper-inline">后缀</span>
                    <el-input v-model="item.encSuffix" style="max-width: 180px; margin-left: 10px" placeholder=".bin / 默认原文件名后缀" />
                  </el-form-item>
                  <el-form-item label="备注">
                    <el-input v-model="item.describe" style="max-width: 280px" placeholder="备注描述" />
                  </el-form-item>
                  <el-form-item label="路径">
                    <el-input v-model="item.encPath" style="max-width: 420px" placeholder="多个目录用逗号隔开" />
                    <span class="helper-text">example: encrypt/*</span>
                  </el-form-item>
                  <el-form-item label="子密码">
                    <span class="helper-inline">根据文件夹名字自动识别文件夹秘钥</span>
                    <el-button type="success" size="small" style="margin-left: 10px" @click="checkFoldName(item)">获取</el-button>
                  </el-form-item>
                </div>
              </div>
            </div>
          </el-collapse-item>
        </el-collapse>

        <div class="footer-actions">
          <el-button type="primary" @click="saveAlistConfig">保存服务配置</el-button>
        </div>

        <el-dialog v-model="dialogFolderFormVisible" title="获取文件夹密文" style="min-width: 320px">
          <el-tabs v-model="activeName" class="demo-tabs">
            <el-tab-pane label="加密名字" name="encode">
              <el-form :model="folderForm">
                <el-form-item label="文件夹名称">
                  <el-input v-model="folderForm.folderName" style="max-width: 260px" placeholder="folder name" />
                </el-form-item>
                <el-form-item label="算法类型">
                  <el-radio-group v-model="folderForm.folderEncType" style="margin: 0 15px" size="small">
                    <el-radio label="aesctr" border>AES-CTR</el-radio>
                    <el-radio label="rc4" border>RC4</el-radio>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="文件夹密码">
                  <el-input v-model="folderForm.folderPasswd" style="max-width: 260px" placeholder="123456" />
                </el-form-item>
                <el-form-item label="加密结果">
                  {{ folderForm.folderNameEnc }}
                </el-form-item>
                <el-button type="success" @click="encodeFoldName">查询</el-button>
              </el-form>
            </el-tab-pane>
            <el-tab-pane label="解密名字" name="decode">
              <el-form :model="folderForm">
                <el-form-item label="文件夹名称">
                  <el-input v-model="folderForm.folderNameEnc" style="max-width: 260px" placeholder="folder name" />
                </el-form-item>
                <el-form-item label="算法类型">
                  {{ folderForm.folderEncType }}
                </el-form-item>
                <el-form-item label="文件夹密码">
                  {{ folderForm.folderPasswd }}
                </el-form-item>
                <el-button type="success" @click="decodeFoldName">解密</el-button>
              </el-form>
            </el-tab-pane>
          </el-tabs>
        </el-dialog>
      </el-form>
    </div>
  </div>
</template>
<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useConfigStore } from '@/store/config'
import { getAlistConfigReq, saveAlistConfigReq, encodeFoldNameReq, decodeFoldNameReq } from '@/api/user'
import { Delete } from '@element-plus/icons-vue'

const labelPosition = ref('right')
const dialogFolderFormVisible = ref(false)
const activeName = ref('encode')
const expandedSections = ref(['connection', 'password'])

const { setLanguage } = useConfigStore()
const changeLanguage = (langParam) => {
  setLanguage(langParam)
}
void changeLanguage

const folderForm = reactive({
  folderName: 'my video',
  encType: 'aesctr',
  folderPasswd: '123456',
  folderNameEnc: '',
  folderEncType: 'rc4',
  password: ''
})

const alistConfigForm = reactive({
  name: '',
  path: '/*',
  describe: '',
  serverHost: '192.168.1.100',
  serverPort: '5244',
  https: false,
  passwdList: [
    {
      id: Math.random(),
      password: '123456',
      encType: 'aesctr',
      enable: false,
      encName: false,
      encSuffix: '',
      describe: 'my video',
      encPath: '333'
    }
  ]
})

const addPasswd = () => {
  alistConfigForm.passwdList.push({
    id: Math.random(),
    password: '123456',
    encType: 'aesctr',
    enable: true,
    encName: false,
    encSuffix: '',
    describe: 'my video',
    encPath: '/aliyun/encrypt/*'
  })
}

const delPasswd = (index) => {
  alistConfigForm.passwdList.splice(index, 1)
}

const checkFoldName = (item) => {
  dialogFolderFormVisible.value = true
  folderForm.password = item.password
  folderForm.encType = item.encType
}

const encodeFoldName = async () => {
  const res = await encodeFoldNameReq(folderForm)
  folderForm.folderNameEnc = `${folderForm.folderName}_${res.data.folderNameEnc}`
}

const decodeFoldName = async () => {
  const res = await decodeFoldNameReq(folderForm)
  folderForm.folderPasswd = res.data.folderPasswd
  folderForm.folderEncType = res.data.folderEncType
}

const saveAlistConfig = () => {
  for (const passwdInfo of alistConfigForm.passwdList) {
    if (typeof passwdInfo.encPath === 'string') {
      passwdInfo.encPath = passwdInfo.encPath
        .split(',')
        .map(item => item.trim())
        .filter(item => item.length > 0)
        .join(',')
    }
  }
  saveAlistConfigReq(alistConfigForm).then(res => {
    ElMessage.success(res.msg)
  })
}

onMounted(async () => {
  const res = await getAlistConfigReq()
  for (const passwdInfo of res.data.passwdList) {
    passwdInfo.id = Math.random()
    if (Array.isArray(passwdInfo.encPath)) {
      passwdInfo.encPath = passwdInfo.encPath.join(',')
    } else if (typeof passwdInfo.encPath !== 'string') {
      passwdInfo.encPath = ''
    }
  }
  Object.assign(alistConfigForm, res.data)
})
</script>

<style scoped lang="scss">
.setting-alist-page {
  padding: 6px 0 30px;
  color: var(--el-text-color-primary);
}

.setting-alist-shell {
  max-width: 1320px;
  margin: 0 auto;
  display: grid;
  gap: 24px;
}

.setting-form {
  padding: 24px;
}

.setting-collapse {
  border: none;
  background: transparent;
}

.section-banner {
  display: inline-flex;
  align-items: center;
  min-height: 42px;
  padding: 0 18px;
  border-radius: 999px;
  border: 1px solid var(--app-border-color);
  background: linear-gradient(135deg, var(--app-surface-soft) 0%, var(--app-surface) 100%);
  color: var(--el-text-color-primary);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 0.04em;
}

.section-banner--accent {
  background: linear-gradient(135deg, var(--el-color-primary-light-3) 0%, var(--el-color-primary) 100%);
  color: #fff;
}

.section-body {
  padding: 18px 4px 12px;
  display: grid;
  gap: 18px;
}

.helper-inline {
  margin-left: 12px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.passwd-list {
  display: grid;
  gap: 14px;
}

.passwd-card {
  border: 1px solid var(--app-border-color);
  border-radius: var(--app-radius-lg);
  background: linear-gradient(180deg, var(--app-surface-soft), var(--app-surface));
  box-shadow: var(--app-shadow-md);
  padding: 16px;
}

.passwd-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  color: var(--el-text-color-primary);
}

.footer-actions {
  margin-top: 18px;
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

:deep(.el-collapse-item__header) {
  height: auto;
  line-height: normal;
  padding: 0;
  border: none;
  background: transparent;
}

:deep(.el-collapse-item__wrap) {
  border: none;
  background: transparent;
}

:deep(.el-collapse-item__content) {
  padding-bottom: 8px;
}

:deep(.el-form-item) {
  margin-bottom: 18px;
  align-items: flex-start;
}

:deep(.el-form-item__content) {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px 12px;
  line-height: 1.7;
}

:deep(.el-form-item__label) {
  color: var(--el-text-color-primary);
  font-weight: 600;
}

:deep(.el-input__wrapper),
:deep(.el-textarea__inner) {
  width: 100%;
}

:deep(.el-input__inner),
:deep(.el-textarea__inner),
:deep(.el-radio__label),
:deep(.el-checkbox__label) {
  color: var(--el-text-color-primary);
}

@media (max-width: 900px) {
  .setting-alist-shell {
    gap: 18px;
  }

  .section-body {
    padding: 16px 0 8px;
  }

  .setting-form {
    padding: 18px;
  }
}
</style>
