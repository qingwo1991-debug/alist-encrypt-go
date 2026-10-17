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
vi.mock('vue-router', () => ({ useRoute: () => ({ path: '/setting-alist/index' }), useRouter: () => ({ push: vi.fn() }) }))
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
  saveProxyRoutingConfigReq,
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
const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

const mountSettings = async () => {
  wrapper = mount(AlistSettings, { global: { stubs: elementStubs } })
  await flushPromises()
  return wrapper.vm.$.setupState
}

describe('Alist password rule defaults', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    saveProxyRoutingConfigReq.mockReset()
    saveProxyRoutingConfigReq.mockResolvedValue({ msg: 'saved' })
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
    vi.useRealTimers()
  })

  it.each(['config', 'scheme', 'dictionary', 'routing', 'stats'])('does not start a late poll after unmount during %s load', async (stage) => {
    const request = deferred()
    const mocks = { config: getAlistConfigReq, scheme: getSchemeConfigReq, dictionary: getProxyDomainDictionaryReq, routing: getProxyRoutingConfigReq, stats: getStatsReq }
    mocks[stage].mockReturnValueOnce(request.promise)
    const setup = await mountSettings()
    const previousHost = setup.alistConfigForm.serverHost
    wrapper.unmount()
    wrapper = undefined
    request.resolve({ data: { passwdList: [], serverHost: 'late-host', providers: [] } })
    await flushPromises()
    await vi.advanceTimersByTimeAsync(30000)
    expect(vi.getTimerCount()).toBe(0)
    expect(setup.alistConfigForm.serverHost).toBe(previousHost)
    if (stage === 'stats') expect(getStatsReq.mock.calls[0][0].signal.aborted).toBe(true)
  })

  it('serializes slow polling and manual refresh and clears pending polls on unmount', async () => {
    const setup = await mountSettings()
    const request = deferred()
    getStatsReq.mockReturnValueOnce(request.promise)
    await vi.advanceTimersByTimeAsync(10000)
    const manual = setup.refreshProbeStats(false)
    await vi.advanceTimersByTimeAsync(30000)
    expect(getStatsReq).toHaveBeenCalledTimes(2)
    request.resolve({ data: {} })
    await manual
    await flushPromises()
    expect(vi.getTimerCount()).toBe(1)
    wrapper.unmount()
    wrapper = undefined
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps polling after an initial stats failure', async () => {
    getStatsReq.mockRejectedValueOnce(new Error('offline'))
    await mountSettings()
    await vi.advanceTimersByTimeAsync(10000)
    expect(getStatsReq).toHaveBeenCalledTimes(2)
  })

  it('holds the shared save lock through both Alist and scheme saves and releases on failure', async () => {
    const setup = await mountSettings()
    const request = deferred()
    saveSchemeConfigReq.mockReturnValueOnce(request.promise)
    const first = setup.saveAlistConfig()
    await flushPromises()
    await setup.saveAlistConfig()
    await setup.saveProxyRouting()
    expect(saveAlistConfigReq).toHaveBeenCalledTimes(1)
    expect(saveProxyRoutingConfigReq).not.toHaveBeenCalled()
    request.resolve({ data: {} })
    await first
    saveAlistConfigReq.mockRejectedValueOnce(new Error('failed'))
    await setup.saveAlistConfig()
    expect(setup.savingConfig).toBe(false)
    await setup.saveProxyRouting()
    expect(saveProxyRoutingConfigReq).toHaveBeenCalledTimes(1)
  })

  it('defaults legacy playback config to standard and shows the saved profile, not unsaved edits', async () => {
    const setup = await mountSettings()
    expect(setup.alistConfigForm.playbackProfile).toBe('standard')
    expect(setup.currentPlaybackProfile).toBe('standard')
    expect(wrapper.text()).toContain('Current Playback Profile')

    setup.alistConfigForm.playbackProfile = 'trusted_local'
    expect(setup.currentPlaybackProfile).toBe('standard')
    await setup.saveAlistConfig()
    expect(saveAlistConfigReq.mock.calls[0][0].playbackProfile).toBe('trusted_local')
    expect(setup.currentPlaybackProfile).toBe('trusted_local')
  })

  it('loads trusted_local and preserves the current profile when saving fails', async () => {
    getAlistConfigReq.mockResolvedValueOnce({ data: { passwdList: [], playbackProfile: 'trusted_local' } })
    const setup = await mountSettings()
    expect(setup.currentPlaybackProfile).toBe('trusted_local')
    setup.alistConfigForm.playbackProfile = 'standard'
    saveAlistConfigReq.mockRejectedValueOnce(new Error('save failed'))
    await setup.saveAlistConfig()
    expect(setup.currentPlaybackProfile).toBe('trusted_local')
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
