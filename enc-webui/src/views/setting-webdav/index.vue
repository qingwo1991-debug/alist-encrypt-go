<template>
  <div class="webdav-page scroll-y">
    <div class="admin-page webdav-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">WebDAV Gateway</div>
          <div class="page-title">WebDAV 服务配置</div>
          <div class="page-subtitle">
            统一管理多个 WebDAV 服务实例、密码规则和目录映射，保持与主服务配置一致的卡片结构和操作节奏。
          </div>
          <div class="hero-pills">
            <div class="hero-pill">
              <div class="hero-pill__label">已配置服务</div>
              <div class="hero-pill__value">{{ configList.length }}</div>
              <div class="hero-pill__meta">支持多实例并行管理。</div>
            </div>
            <div class="hero-pill">
              <div class="hero-pill__label">已启用服务</div>
              <div class="hero-pill__value">{{ enabledCount }}</div>
              <div class="hero-pill__meta">运行状态来自当前配置列表。</div>
            </div>
            <div class="hero-pill">
              <div class="hero-pill__label">密码规则</div>
              <div class="hero-pill__value">{{ passwordRuleCount }}</div>
              <div class="hero-pill__meta">多路径、多算法配置统一维护。</div>
            </div>
          </div>
        </div>
        <div class="page-actions">
          <el-button type="primary" @click="addConfig">新增配置</el-button>
        </div>
      </section>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">服务列表</div>
            <div class="panel-card__subtitle">卡片化展示实例地址、状态和加密规则，便于快速定位与编辑。</div>
          </div>
          <div class="muted-text">新增后重启生效</div>
        </div>

        <div v-if="configList.length" class="service-grid">
          <div v-for="config in configList" :key="config.id" class="service-card">
            <div class="service-card__header">
              <div>
                <div class="service-card__title">{{ config.name }}</div>
                <div class="service-card__meta">{{ config.describe || 'WebDAV 服务' }}</div>
              </div>
              <el-switch v-model="config.enable" @change="updateWebdavConfig(config)" />
            </div>

            <div class="service-card__body">
              <div class="service-card__row"><span>服务器</span><strong>{{ config.serverHost }}</strong></div>
              <div class="service-card__row"><span>端口</span><strong>{{ config.serverPort }}</strong></div>
              <div class="service-card__row"><span>主目录</span><strong>{{ config.path }}</strong></div>
              <div class="service-card__row"><span>密码规则</span><strong>{{ config.passwdList?.length || 0 }}</strong></div>
            </div>

            <div class="service-card__actions">
              <el-button type="primary" plain @click="editConfig(config)">编辑</el-button>
              <el-button type="danger" plain @click="delWebdavConfig(config.id)">删除</el-button>
            </div>
          </div>
        </div>

        <div v-else class="empty-state">暂无 WebDAV 服务配置，点击右上角开始新增。</div>
      </section>
    </div>

    <el-dialog v-model="dialogFormVisible" title="WebDAV 配置" width="min(960px, 92vw)">
      <div class="dialog-shell">
        <section class="panel-card panel-card--soft">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">基础连接</div>
              <div class="panel-card__subtitle">定义实例名称、地址、端口和服务根路径。</div>
            </div>
          </div>

          <el-form :model="configFormTemp" label-width="88px">
            <div class="form-grid">
              <el-form-item label="服务名称">
                <el-input v-model="configFormTemp.name" placeholder="webdav" />
              </el-form-item>
              <el-form-item label="服务器">
                <el-input v-model="configFormTemp.serverHost" placeholder="127.0.0.1" />
              </el-form-item>
              <el-form-item label="端口">
                <el-input v-model="configFormTemp.serverPort" placeholder="5244" />
              </el-form-item>
              <el-form-item label="主目录">
                <el-input v-model="configFormTemp.path" placeholder="/webdav/*" />
              </el-form-item>
            </div>
            <el-form-item label="描述">
              <el-input v-model="configFormTemp.describe" placeholder="webdav 服务" />
            </el-form-item>
            <el-form-item label="启用">
              <el-switch v-model="configFormTemp.enable" />
              <span class="helper-text">修改目录映射后重启服务生效。</span>
            </el-form-item>
          </el-form>
        </section>

        <section class="panel-card">
          <div class="panel-card__header">
            <div>
              <div class="panel-card__title">密码规则</div>
              <div class="panel-card__subtitle">按路径配置加密算法、文件名策略和备注说明。</div>
            </div>
            <el-button type="success" @click="addPasswd">添加规则</el-button>
          </div>

          <div class="stack-grid">
            <div v-for="(item, index) in configFormTemp.passwdList" :key="item.id" class="passwd-card">
              <div class="passwd-card__header">
                <div>
                  <div class="passwd-card__title">规则 {{ index + 1 }}</div>
                  <div class="passwd-card__meta">多目录可用逗号分隔，支持文件名加密和后缀策略。</div>
                </div>
                <el-button type="danger" :icon="Delete" circle @click="delPasswd(index)" />
              </div>

              <el-form label-width="70px">
                <el-form-item label="算法">
                  <el-radio-group v-model="item.encType" size="small">
                    <el-radio label="rc4" border>RC4</el-radio>
                    <el-radio label="aesctr" border>AES-CTR</el-radio>
                    <el-radio label="chacha20" border>ChaCha20</el-radio>
                  </el-radio-group>
                  <span class="helper-inline">启用</span>
                  <el-switch v-model="item.enable" />
                </el-form-item>
                <div class="form-grid">
                  <el-form-item label="密码">
                    <el-input v-model="item.password" placeholder="123456" />
                  </el-form-item>
                  <el-form-item label="备注">
                    <el-input v-model="item.describe" placeholder="my video" />
                  </el-form-item>
                  <el-form-item label="后缀">
                    <el-input v-model="item.encSuffix" placeholder=".bin / 默认原文件名后缀" />
                  </el-form-item>
                  <el-form-item label="路径">
                    <el-input v-model="item.encPath" placeholder="/dav/encrypt/*" />
                  </el-form-item>
                </div>
                <el-form-item label="文件名">
                  <span class="helper-inline">加密</span>
                  <el-switch v-model="item.encName" />
                </el-form-item>
              </el-form>
            </div>
          </div>
        </section>

        <div class="page-actions dialog-actions">
          <el-button @click="dialogFormVisible = false">取消</el-button>
          <el-button type="primary" @click="saveWebdavConfig()">保存配置</el-button>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import { delWebdavConfigReq, getWebdavConfigReq, saveWebdavConfigReq, updateWebdavConfigReq } from '@/api/user'
import { ElMessageBox, ElMessage } from 'element-plus'
import { Delete } from '@element-plus/icons-vue'

const dialogFormVisible = ref(false)
const configList = reactive([])

const configFormTemp = reactive({})
const configTemp = {
  name: 'webdav',
  path: '/webdav/*',
  describe: 'webdav服务',
  serverHost: '192.168.1.100',
  serverPort: '5244',
  https: false,
  enable: true,
  passwdList: [
    {
      id: Math.random(),
      password: '123456',
      encType: 'aesctr',
      enable: false,
      encName: false,
      encSuffix: '',
      describe: 'my video',
      encPath: '/aliyun/encrypt/*'
    }
  ]
}

const resetConfigTemp = () => {
  Object.assign(configFormTemp, JSON.parse(JSON.stringify(configTemp)))
}

resetConfigTemp()

const enabledCount = computed(() => configList.filter((item) => item.enable).length)
const passwordRuleCount = computed(() => configList.reduce((sum, item) => sum + (item.passwdList?.length || 0), 0))

const addPasswd = () => {
  configFormTemp.passwdList.push({
    id: Math.random(),
    password: '123456',
    encType: 'aesctr',
    enable: true,
    encName: false,
    encSuffix: '',
    describe: 'my video',
    encPath: '/dav/encrypt/*'
  })
}

const delPasswd = (index) => {
  configFormTemp.passwdList.splice(index, 1)
}

const editConfig = (config) => {
  dialogFormVisible.value = true
  Object.assign(configFormTemp, JSON.parse(JSON.stringify(config)))
}

const addConfig = () => {
  dialogFormVisible.value = true
  resetConfigTemp()
}

const updateWebdavConfig = async (config) => {
  const result = await updateWebdavConfigReq(config)
  refreshConfigList(result)
}

const saveWebdavConfig = async () => {
  let result = null
  if (configFormTemp.id) {
    result = await updateWebdavConfigReq(configFormTemp)
  } else {
    result = await saveWebdavConfigReq(configFormTemp)
  }
  dialogFormVisible.value = false
  refreshConfigList(result)
}

const delWebdavConfig = async (id) => {
  ElMessageBox.confirm('Are you sure to delete?').then(async () => {
    const result = await delWebdavConfigReq({ id })
    refreshConfigList(result)
    dialogFormVisible.value = false
    ElMessage(result.msg)
  })
}

const refreshConfigList = async (result) => {
  const res = result || (await getWebdavConfigReq())
  configList.splice(0, configList.length)
  res.data.forEach((element) => {
    const passwdList = element.passwdList || []
    for (const passwdInfo of passwdList) {
      passwdInfo.id = Math.random()
    }
    configList.push(element)
  })
}

onMounted(async () => {
  refreshConfigList()
})
</script>

<style scoped lang="scss">
.webdav-page {
  padding: 6px 0 30px;
}

.webdav-shell {
  max-width: 1320px;
  margin: 0 auto;
}

.service-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 18px;
}

.service-card,
.passwd-card {
  border: 1px solid var(--app-border-color);
  border-radius: var(--app-radius-lg);
  background: linear-gradient(180deg, var(--app-surface-soft), var(--app-surface));
  box-shadow: var(--app-shadow-md);
}

.service-card {
  padding: 18px;
}

.service-card__header,
.passwd-card__header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}

.service-card__title,
.passwd-card__title {
  font-size: 18px;
  font-weight: 700;
  color: var(--el-text-color-primary);
}

.service-card__meta,
.passwd-card__meta,
.empty-state {
  margin-top: 6px;
  font-size: 13px;
  line-height: 1.7;
  color: var(--el-text-color-secondary);
}

.service-card__body {
  display: grid;
  gap: 12px;
  margin-top: 18px;
}

.service-card__row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border-radius: var(--app-radius-sm);
  background: var(--app-surface-muted);
  color: var(--el-text-color-regular);
}

.service-card__row strong {
  color: var(--el-text-color-primary);
}

.service-card__actions {
  display: flex;
  gap: 12px;
  margin-top: 18px;
}

.dialog-shell {
  display: grid;
  gap: 18px;
}

.dialog-actions {
  justify-content: flex-end;
}

.passwd-card {
  padding: 18px;
}

.helper-inline {
  margin: 0 10px 0 12px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

:deep(.el-form-item__content) {
  gap: 10px;
}

@media (max-width: 768px) {
  .service-card__actions {
    flex-direction: column;
  }
}
</style>
