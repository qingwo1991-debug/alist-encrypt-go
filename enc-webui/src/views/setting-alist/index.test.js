import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/user', () => ({
  cleanupLegacyBoltDBReq: vi.fn(),
  decodeFoldNameReq: vi.fn(),
  encodeFoldNameReq: vi.fn(),
  getAlistConfigReq: vi.fn(),
  getProxyDomainDictionaryReq: vi.fn(),
  getProxyRoutingConfigReq: vi.fn(),
  getSchemeConfigReq: vi.fn(),
  getStatsReq: vi.fn(),
  refreshProxyDomainDictionaryReq: vi.fn(),
  runDirSyncReq: vi.fn(),
  saveAlistConfigReq: vi.fn(),
  saveProxyRoutingConfigReq: vi.fn(),
  saveSchemeConfigReq: vi.fn(),
  validateScanConfigReq: vi.fn()
}))
vi.mock('element-plus', () => {
  const ElMessage = vi.fn()
  ElMessage.error = vi.fn()
  ElMessage.success = vi.fn()
  ElMessage.warning = vi.fn()
  return { ElMessage }
})
vi.mock('@element-plus/icons-vue', () => ({ Delete: {} }))

import {
  getAlistConfigReq,
  getProxyDomainDictionaryReq,
  getProxyRoutingConfigReq,
  getSchemeConfigReq,
  getStatsReq,
  saveAlistConfigReq,
  saveSchemeConfigReq
} from '@/api/user'
import { ElMessage } from 'element-plus'
import AlistSettings from './index.vue'

const elementStubs = {
  'el-button': true,
  'el-collapse': true,
  'el-collapse-item': true,
  'el-dialog': true,
  'el-form': true,
  'el-form-item': true,
  'el-input': true,
  'el-option': true,
  'el-pagination': true,
  'el-radio': true,
  'el-radio-group': true,
  'el-select': true,
  'el-switch': true,
  'el-tab-pane': true,
  'el-tabs': true
}

let wrapper
let setIntervalSpy

const mountSettings = async () => {
  wrapper = mount(AlistSettings, { global: { stubs: elementStubs } })
  await flushPromises()
  return wrapper.vm.$.setupState
}

describe('Alist password rule defaults', () => {
  beforeEach(() => {
    setIntervalSpy = vi.spyOn(window, 'setInterval').mockReturnValue(1)
    getAlistConfigReq.mockReset()
    getAlistConfigReq.mockResolvedValue({ data: { passwdList: [] } })
    getSchemeConfigReq.mockReset()
    getSchemeConfigReq.mockResolvedValue({ data: {} })
    getProxyDomainDictionaryReq.mockReset()
    getProxyDomainDictionaryReq.mockResolvedValue({ data: { providers: [] } })
    getProxyRoutingConfigReq.mockReset()
    getProxyRoutingConfigReq.mockResolvedValue({ data: null })
    getStatsReq.mockReset()
    getStatsReq.mockResolvedValue({ data: {} })
    saveAlistConfigReq.mockReset()
    saveAlistConfigReq.mockResolvedValue({ msg: 'saved' })
    saveSchemeConfigReq.mockReset()
    saveSchemeConfigReq.mockResolvedValue({ data: {} })
    ElMessage.error.mockReset()
    ElMessage.success.mockReset()
  })

  afterEach(() => {
    wrapper?.unmount()
    wrapper = undefined
    setIntervalSpy.mockRestore()
  })

  it('creates new rules blank and disabled', async () => {
    const setup = await mountSettings()

    setup.addPasswd()
    const rule = setup.alistConfigForm.passwdList.at(-1)

    expect(rule.password).toBe('')
    expect(rule.enable).toBe(false)
  })

  it('does not persist an enabled rule with a blank password', async () => {
    const setup = await mountSettings()
    setup.addPasswd()
    setup.alistConfigForm.passwdList[0].enable = true
    setup.alistConfigForm.passwdList[0].password = '   '

    await setup.saveAlistConfig()

    expect(saveAlistConfigReq).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('已启用的密码规则必须填写密码')
  })

  it('does not save scheme settings or report success when Alist save rejects', async () => {
    saveAlistConfigReq.mockRejectedValueOnce(new Error('save failed'))
    const setup = await mountSettings()
    getSchemeConfigReq.mockClear()
    saveSchemeConfigReq.mockClear()

    await setup.saveAlistConfig()

    expect(getSchemeConfigReq).not.toHaveBeenCalled()
    expect(saveSchemeConfigReq).not.toHaveBeenCalled()
    expect(ElMessage.success).not.toHaveBeenCalled()
  })
})
