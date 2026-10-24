<template>
  <div class="cloud-page scroll-y">
    <div class="admin-page cloud-shell">
      <section class="page-hero">
        <div class="page-hero__content">
          <div class="page-eyebrow">WoPan Storage</div>
          <h1 class="page-title">联通沃盘容量与回收站</h1>
          <div class="page-subtitle">查看个人账号总容量；回收站清空是不可恢复的账号级操作。</div>
        </div>
        <div class="page-actions">
          <el-button data-testid="reload-storages" :loading="storagesLoading" :disabled="busy" @click="loadStorages">刷新挂载列表</el-button>
        </div>
      </section>

      <section class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">沃盘挂载</div>
            <div class="panel-card__subtitle">挂载仅用于选择账号，不代表容量或清空操作的目录范围。</div>
          </div>
        </div>
        <el-alert v-if="storagesError" class="cloud-alert" type="error" :closable="false" show-icon :title="storagesError" />
        <div v-if="!storagesLoading && !storagesError && storages.length === 0" class="empty-hint" role="status">
          暂无沃盘挂载。请先配置中国联通沃盘存储，再刷新挂载列表。
        </div>
        <label v-if="storages.length" class="mount-field">
          <span>选择挂载</span>
          <el-select v-model="selectedId" data-testid="storage-select" aria-label="选择沃盘挂载" :disabled="busy || storagesLoading" placeholder="请选择沃盘挂载">
            <el-option v-for="storage in storages" :key="storage.storage_id" :value="storage.storage_id" :label="storageLabel(storage)" />
          </el-select>
        </label>
        <div v-if="selectedStorage" class="mount-meta">
          <el-tag :type="selectedStorage.scope === 'personal' ? 'primary' : 'info'">{{ selectedStorage.scope === 'personal' ? '个人账号' : '家庭空间' }}</el-tag>
          <span>挂载：{{ selectedStorage.mount_path }}</span>
          <span>存储 ID：{{ selectedStorage.storage_id }}</span>
        </div>
        <el-alert v-if="selectedStorage && !canReadQuota" class="cloud-alert" type="warning" :closable="false" show-icon :title="unsupportedReason" />
      </section>

      <section v-if="canReadQuota" class="panel-card">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">个人账号总容量</div>
            <div class="panel-card__subtitle">包含此个人账号的所有挂载与目录，不是当前挂载子目录的容量。不使用家庭空间容量替代。</div>
          </div>
          <el-button data-testid="refresh-quota" type="primary" plain :loading="quotaLoading" :disabled="busy || storagesLoading" @click="loadQuota">刷新容量</el-button>
        </div>
        <el-alert v-if="quotaError" class="cloud-alert" type="error" :closable="false" show-icon :title="quotaError" />
        <div v-if="!quota && !quotaError" class="empty-hint" role="status">{{ quotaLoading ? '正在查询账号容量…' : '容量未知，请刷新重试。' }}</div>
        <template v-if="quota">
          <div class="capacity-grid">
            <div v-for="card in capacityCards" :key="card.key" class="capacity-card" :data-testid="card.key">
              <div class="capacity-card__label">{{ card.label }}</div>
              <div class="capacity-card__value">{{ formatBytes(card.value) }}</div>
              <div class="capacity-card__raw">{{ rawBytes(card.value) }}</div>
            </div>
          </div>
          <div class="quota-progress">
            <span>已用比例：{{ usedPercentage === null ? '未知' : `${usedPercentage.toFixed(2)}%` }}</span>
            <el-progress v-if="usedPercentage !== null" :percentage="usedPercentage" :show-text="false" />
          </div>
          <p class="cloud-note">上次查询：{{ formatTime(quota.checked_at) }}。容量为查询时账号报告值；实际清理和容量回收可能延迟。</p>
        </template>
        <p class="cloud-note">回收站占用：未知。不估算可回收容量，也不通过容量变化判定清空是否完成。</p>
      </section>

      <section v-if="selectedStorage" class="panel-card recycle-panel">
        <div class="panel-card__header">
          <div>
            <div class="panel-card__title">回收站</div>
            <div class="panel-card__subtitle">清空将影响整个个人账号的全部回收站文件，而不只是当前加密目录。</div>
          </div>
          <el-button v-if="canClearRecycle" data-testid="open-clear" type="danger" plain :disabled="busy || storagesLoading" @click="openRecycleDialog">清空回收站</el-button>
        </div>
        <p v-if="!canClearRecycle" class="cloud-note">{{ reasonText(selectedStorage.unsupported_reason) || '当前挂载不支持清空个人账号回收站。' }}</p>
        <el-alert v-if="clearNotice" data-testid="clear-notice" type="info" :closable="false" show-icon :title="clearNotice" />
      </section>
    </div>

    <el-dialog
      v-model="dialogVisible"
      title="危险操作：清空个人账号全部回收站"
      width="min(620px, 94vw)"
      :close-on-click-modal="false"
      :close-on-press-escape="!clearing"
      :show-close="!clearing"
      :before-close="beforeDialogClose"
    >
      <el-alert type="error" :closable="false" show-icon title="永久删除，无法恢复" />
      <p class="danger-copy">此操作影响整个个人账号、所有挂载的全部回收站文件，不仅是当前挂载或加密目录。请确认账号无误。</p>
      <p>当前挂载：<strong>{{ selectedStorage?.mount_path }}</strong>（存储 ID：{{ selectedId }}）</p>
      <p>回收站占用未知，无法预估可释放空间。请求提交后，实际清理与容量回收可能延迟。</p>
      <el-alert v-if="dialogError" data-testid="dialog-error" class="cloud-alert" type="error" :closable="false" show-icon :title="dialogError" />
      <el-button data-testid="prepare-clear" :loading="preparing" :disabled="busy || !!prepared" @click="prepareRecycle">获取确认凭证</el-button>
      <div v-if="prepared" class="confirmation-fields">
        <p v-if="prepared.warning" class="danger-copy">{{ prepared.warning }}</p>
        <p>凭证有效期至：{{ formatTime(prepared.expires_at) }}</p>
        <label for="wopan-confirmation">请逐字输入：<strong>{{ CONFIRMATION_PHRASE }}</strong></label>
        <el-input id="wopan-confirmation" v-model="confirmationInput" data-testid="confirmation-input" :disabled="clearing" autocomplete="off" :placeholder="CONFIRMATION_PHRASE" />
      </div>
      <template #footer>
        <el-button data-testid="cancel-clear" :disabled="clearing" @click="closeRecycleDialog">取消</el-button>
        <el-button data-testid="confirm-clear" type="danger" :loading="clearing" :disabled="!canSubmitClear" @click="clearRecycle">永久清空</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { clearWopanRecycleReq, getWopanQuotaReq, getWopanStoragesReq, prepareWopanRecycleReq } from '@/api/cloud-storage'

const CONFIRMATION_PHRASE = '清空个人账号全部回收站'
const storages = ref([])
const selectedId = ref(null)
const storagesLoading = ref(false)
const storagesError = ref('')
const quota = ref(null)
const quotaLoading = ref(false)
const quotaError = ref('')
const dialogVisible = ref(false)
const preparing = ref(false)
const clearing = ref(false)
const prepared = ref(null)
const confirmationInput = ref('')
const dialogError = ref('')
const clearNotice = ref('')
let disposed = false
let storageGeneration = 0
let quotaGeneration = 0
let dialogGeneration = 0
let storageController
let quotaController
let prepareController
let expiryTimer

const selectedStorage = computed(() => storages.value.find(storage => storage.storage_id === selectedId.value))
const canReadQuota = computed(() => selectedStorage.value?.scope === 'personal' && selectedStorage.value.available === true)
const canClearRecycle = computed(() => canReadQuota.value && selectedStorage.value.clear_supported === true)
const busy = computed(() => preparing.value || clearing.value)
const unsupportedReason = computed(() => reasonText(selectedStorage.value?.unsupported_reason) || (
  selectedStorage.value?.scope === 'family' ? '家庭空间不支持个人账号容量查询或回收站清空，不会回退到个人容量。' : '此挂载暂不可用，请检查存储配置后重试。'
))
const capacityCards = computed(() => [
  { key: 'total-bytes', label: '总容量', value: quota.value?.total_bytes },
  { key: 'used-bytes', label: '已使用', value: quota.value?.used_bytes },
  { key: 'available-bytes', label: '剩余可用', value: quota.value?.available_bytes }
])

// Never round the API's decimal strings through Number: values may exceed 2^53.
const parseBytes = value => typeof value === 'string' && /^\d+$/.test(value) ? BigInt(value) : null
const formatBytes = value => {
  const bytes = parseBytes(value)
  if (bytes === null) return '未知'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
  let unit = 0
  let divisor = 1n
  while (unit < units.length - 1 && bytes >= divisor * 1024n) {
    divisor *= 1024n
    unit += 1
  }
  if (unit === 0) return `${bytes} B`
  const hundredths = (bytes * 100n + divisor / 2n) / divisor
  return `${hundredths / 100n}.${String(hundredths % 100n).padStart(2, '0')} ${units[unit]}`
}
const rawBytes = value => parseBytes(value) === null ? '原始字节数未知' : `${value} 字节`
const percentage = (usedValue, totalValue) => {
  const used = parseBytes(usedValue)
  const total = parseBytes(totalValue)
  if (used === null || total === null || total === 0n || used > total) return null
  return Number(used * 10000n / total) / 100
}
const usedPercentage = computed(() => percentage(quota.value?.used_bytes, quota.value?.total_bytes))
const formatTime = value => {
  if (!value) return '未知'
  const time = new Date(value)
  return Number.isNaN(time.getTime()) ? '未知' : time.toLocaleString('zh-CN', { hour12: false })
}
const storageLabel = storage => `${storage.mount_path} · ${storage.scope === 'personal' ? '个人账号' : '家庭空间'} · #${storage.storage_id}${storage.available ? '' : '（不可用）'}`
const errorMessages = {
  local_auth_required: '本地登录已失效，请重新登录。',
  local_admin_required: '需要本地管理员权限。',
  upstream_admin_required: '需要在服务配置中提供上游管理员凭据，普通文件浏览凭据不可用于此功能。',
  origin_not_allowed: '请求来源校验失败，请通过同源管理页面操作。',
  configuration_changed: '服务配置已变化，请刷新挂载列表并重新确认。',
  upstream_unavailable: '无法连接上游存储服务，请检查配置后重试。',
  upstream_invalid_response: '上游存储服务响应无效，请稍后重试。',
  provider_unavailable: '沃盘服务暂不可用，请检查账号登录状态后重试。',
  provider_invalid_response: '沃盘返回的数据无效，请稍后重试。',
  family_not_supported: '家庭空间不支持个人账号容量查询或回收站清空，不会回退到个人容量。',
  storage_unavailable: '此挂载已禁用或尚未就绪，请检查存储配置。',
  storage_credentials_unavailable: '此挂载缺少有效的沃盘账号凭据，请检查存储配置。',
  storage_not_wopan: '所选存储已不是沃盘，请刷新挂载列表。',
  storage_list_limit: '挂载列表超出安全查询上限，请检查上游存储配置。',
  invalid_storage_id: '挂载标识无效，请重新选择挂载。',
  json_content_type_required: '请求格式不正确，需要 JSON 数据。',
  invalid_json: '请求数据无效，请刷新页面后重试。',
  confirmation_unavailable: '暂时无法生成确认凭证，请稍后重试。',
  confirmation_limit: '待确认请求过多，请稍后重新获取凭证。',
  confirmation_invalid: '确认凭证已失效、已使用或不匹配，请重新获取。',
  confirmation_phrase_mismatch: '确认文字不完全一致，请重新获取凭证并逐字输入。',
  storage_changed: '挂载配置已变化，请刷新挂载列表并重新确认。',
  account_changed: '个人账号已变化，请刷新挂载列表并重新确认。',
  clear_in_progress: '此个人账号已有清空请求正在处理，请勿重复提交。',
  clear_outcome_unknown: '清空请求的处理结果暂无法确认，请先核实回收站状态。'
}
const reasonText = reason => typeof reason === 'string' ? (errorMessages[reason] || reason) : ''
const errorText = (error, fallback) => reasonText(error?.response?.data?.msg || error?.response?.data?.message || (typeof error === 'string' ? error : error?.message)) || fallback
const payload = response => {
  if (!response || !['0', '200', '20000'].includes(String(response.code))) throw new Error(response?.msg || '接口响应无效，请重试。')
  return response.data
}
const newController = () => typeof AbortController === 'undefined' ? undefined : new AbortController()
const sameStorage = (data, storage) => data?.storage_id === storage.storage_id && data?.mount_path === storage.mount_path

const invalidateQuota = () => {
  quotaGeneration += 1
  quotaController?.abort()
  quotaLoading.value = false
  quota.value = null
  quotaError.value = ''
}
const resetConfirmation = () => {
  dialogGeneration += 1
  prepareController?.abort()
  window.clearTimeout(expiryTimer)
  prepared.value = null
  confirmationInput.value = ''
  preparing.value = false
}
const closeRecycleDialog = () => {
  if (clearing.value) return
  dialogVisible.value = false
  resetConfirmation()
  dialogError.value = ''
}
const beforeDialogClose = done => {
  if (clearing.value) return
  closeRecycleDialog()
  done()
}

const loadQuota = async () => {
  if (disposed || !canReadQuota.value || busy.value || storagesLoading.value) return
  invalidateQuota()
  const generation = quotaGeneration
  const storage = { ...selectedStorage.value }
  quotaController = newController()
  quotaLoading.value = true
  try {
    const data = payload(await getWopanQuotaReq(storage.storage_id, { signal: quotaController?.signal }))
    if (disposed || generation !== quotaGeneration) return
    if (!sameStorage(data, storage) || data.scope !== 'personal') throw new Error('容量响应与当前个人账号挂载不匹配，请重试。')
    quota.value = data
  } catch (error) {
    if (!disposed && generation === quotaGeneration) quotaError.value = errorText(error, '容量查询失败，请刷新重试。')
  } finally {
    if (!disposed && generation === quotaGeneration) quotaLoading.value = false
  }
}

const loadStorages = async () => {
  if (disposed || storagesLoading.value || busy.value) return
  const generation = ++storageGeneration
  storageController?.abort()
  storageController = newController()
  closeRecycleDialog()
  invalidateQuota()
  storagesLoading.value = true
  storagesError.value = ''
  clearNotice.value = ''
  const previousId = selectedId.value
  // Hide old capabilities while discovering current storage configuration.
  storages.value = []
  selectedId.value = null
  try {
    const data = payload(await getWopanStoragesReq({ signal: storageController?.signal }))
    if (disposed || generation !== storageGeneration) return
    if (!Array.isArray(data?.storages)) throw new Error('挂载列表响应无效，请重试。')
    const ids = new Set()
    for (const storage of data.storages) {
      if (!Number.isSafeInteger(storage?.storage_id) || storage.storage_id <= 0 || ids.has(storage.storage_id) || typeof storage.mount_path !== 'string' || !['personal', 'family'].includes(storage.scope) || typeof storage.available !== 'boolean' || typeof storage.clear_supported !== 'boolean') {
        throw new Error('挂载列表响应无效，请重试。')
      }
      ids.add(storage.storage_id)
    }
    storages.value = data.storages
    selectedId.value = storages.value.some(storage => storage.storage_id === previousId) ? previousId : (storages.value[0]?.storage_id ?? null)
  } catch (error) {
    if (!disposed && generation === storageGeneration) storagesError.value = errorText(error, '挂载列表加载失败，请重试。')
  } finally {
    if (!disposed && generation === storageGeneration) {
      storagesLoading.value = false
      await loadQuota()
    }
  }
}

const openRecycleDialog = () => {
  if (disposed || !canClearRecycle.value || busy.value || storagesLoading.value) return
  resetConfirmation()
  dialogError.value = ''
  clearNotice.value = ''
  dialogVisible.value = true
}
const prepareRecycle = async () => {
  if (disposed || !dialogVisible.value || !canClearRecycle.value || busy.value || prepared.value) return
  resetConfirmation()
  dialogError.value = ''
  const generation = dialogGeneration
  const storage = { ...selectedStorage.value }
  prepareController = newController()
  preparing.value = true
  try {
    const data = payload(await prepareWopanRecycleReq(storage.storage_id, { signal: prepareController?.signal }))
    if (disposed || generation !== dialogGeneration || !dialogVisible.value) return
    const expiresAt = Date.parse(data?.expires_at)
    if (!sameStorage(data, storage) || data.scope !== 'personal_account' || data.confirmation_phrase !== CONFIRMATION_PHRASE || typeof data.confirmation_token !== 'string' || !data.confirmation_token.trim() || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new Error('确认凭证无效、已过期或与当前个人账号不匹配，请重新获取。')
    }
    prepared.value = data
    expiryTimer = window.setTimeout(() => {
      if (generation !== dialogGeneration || disposed) return
      resetConfirmation()
      dialogError.value = '确认凭证已过期，请重新获取。'
    }, Math.min(expiresAt - Date.now(), 2147483647))
  } catch (error) {
    if (!disposed && generation === dialogGeneration) {
      resetConfirmation()
      dialogError.value = errorText(error, '获取确认凭证失败，请重试。')
    }
  } finally {
    if (!disposed && generation === dialogGeneration) preparing.value = false
  }
}
const canSubmitClear = computed(() => dialogVisible.value && canClearRecycle.value && !busy.value && !!prepared.value && sameStorage(prepared.value, selectedStorage.value) && prepared.value.scope === 'personal_account' && prepared.value.confirmation_phrase === CONFIRMATION_PHRASE && confirmationInput.value === CONFIRMATION_PHRASE && Date.parse(prepared.value.expires_at) > Date.now())

const clearRecycle = async () => {
  if (disposed || !canSubmitClear.value) return
  const storage = { ...selectedStorage.value }
  const request = {
    storage_id: storage.storage_id,
    confirmation_token: prepared.value.confirmation_token,
    confirmation_phrase: confirmationInput.value
  }
  // Consume the credential locally before dispatch, including on network failure.
  resetConfirmation()
  const generation = dialogGeneration
  clearing.value = true
  dialogError.value = ''
  try {
    const data = payload(await clearWopanRecycleReq(request))
    if (disposed || generation !== dialogGeneration) return
    if (!['accepted', 'completed'].includes(data?.status) || (data.storage_id !== undefined && data.storage_id !== storage.storage_id) || (data.mount_path !== undefined && data.mount_path !== storage.mount_path)) {
      throw new Error('清空请求结果无法确认，请手动核实；不会自动重试。')
    }
    clearNotice.value = '已提交清空请求，容量回收可能延迟。此提示不代表清空已完成，请稍后手动刷新容量。'
    dialogVisible.value = false
  } catch (error) {
    if (!disposed && generation === dialogGeneration) dialogError.value = `${errorText(error, '清空请求失败。')} 请求可能已发送，不会自动重试；请先核实状态，如需再次操作必须重新获取凭证。`
  } finally {
    if (!disposed) {
      clearing.value = false
      if (generation === dialogGeneration) resetConfirmation()
    }
  }
}

watch(selectedId, () => {
  invalidateQuota()
  resetConfirmation()
  dialogVisible.value = false
  dialogError.value = ''
  clearNotice.value = ''
  if (!storagesLoading.value) loadQuota()
}, { flush: 'sync' })
watch(dialogVisible, visible => {
  if (!visible) resetConfirmation()
}, { flush: 'sync' })
onMounted(loadStorages)
onBeforeUnmount(() => {
  disposed = true
  storageGeneration += 1
  storageController?.abort()
  invalidateQuota()
  resetConfirmation()
})
</script>

<style scoped>
.cloud-page { min-height: 100%; }
.cloud-shell { display: flex; flex-direction: column; gap: 20px; }
.cloud-alert { margin-bottom: 16px; }
.mount-field { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
.mount-field .el-select { width: min(100%, 580px); }
.mount-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin-top: 16px; color: var(--el-text-color-secondary); overflow-wrap: anywhere; }
.capacity-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.capacity-card { padding: 20px; border: 1px solid var(--el-border-color-lighter); border-radius: 12px; background: var(--el-fill-color-light); min-width: 0; }
.capacity-card__label { color: var(--el-text-color-secondary); font-size: 14px; }
.capacity-card__value { margin: 12px 0 8px; font-size: 28px; font-weight: 600; color: var(--el-text-color-primary); overflow-wrap: anywhere; }
.capacity-card__raw { font-size: 12px; color: var(--el-text-color-secondary); overflow-wrap: anywhere; }
.quota-progress { margin-top: 20px; display: grid; gap: 10px; }
.cloud-note { color: var(--el-text-color-secondary); line-height: 1.7; font-size: 13px; }
.recycle-panel { border-color: var(--el-color-danger-light-7); }
.danger-copy { color: var(--el-color-danger); line-height: 1.8; }
.confirmation-fields { display: grid; gap: 12px; margin-top: 20px; }
.confirmation-fields p { margin: 0; }
@media (max-width: 768px) {
  .capacity-grid { grid-template-columns: 1fr; }
  .panel-card__header { flex-wrap: wrap; gap: 12px; }
}
</style>
