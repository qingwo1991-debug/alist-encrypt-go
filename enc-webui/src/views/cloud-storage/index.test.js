import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/cloud-storage', () => ({
  getWopanStoragesReq: vi.fn(),
  getWopanQuotaReq: vi.fn(),
  prepareWopanRecycleReq: vi.fn(),
  clearWopanRecycleReq: vi.fn()
}))
import { clearWopanRecycleReq, getWopanQuotaReq, getWopanStoragesReq, prepareWopanRecycleReq } from '@/api/cloud-storage'
import CloudStorage from './index.vue'

const phrase = '清空个人账号全部回收站'
const personal = { storage_id: 1, mount_path: '/沃盘/加密', scope: 'personal', available: true, clear_supported: true }
const otherPersonal = { ...personal, storage_id: 2, mount_path: '/另一个挂载' }
const family = { ...personal, storage_id: 3, mount_path: '/家庭', scope: 'family' }
const ok = data => ({ code: 0, data })
const quotaData = (storage = personal, overrides = {}) => ({
  storage_id: storage.storage_id,
  mount_path: storage.mount_path,
  scope: 'personal',
  total_bytes: '1099511627776',
  used_bytes: '549755813888',
  available_bytes: '549755813888',
  checked_at: '2026-10-24T08:00:00Z',
  recycle_bin_bytes: null,
  ...overrides
})
const preparation = (overrides = {}) => ({
  storage_id: personal.storage_id,
  mount_path: personal.mount_path,
  confirmation_token: 'opaque-one-time-token',
  confirmation_phrase: phrase,
  expires_at: new Date(Date.now() + 60000).toISOString(),
  warning: '服务端警告：将永久删除个人账号全部回收站。',
  scope: 'personal_account',
  ...overrides
})
const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}
const stubs = {
  'el-button': {
    props: ['disabled', 'loading'],
    template: '<button :disabled="disabled || loading"><slot /></button>'
  },
  'el-select': {
    props: ['modelValue', 'disabled'], emits: ['update:modelValue'],
    template: '<select :value="modelValue" :disabled="disabled" @change="$emit(\'update:modelValue\', Number($event.target.value))"><slot /></select>'
  },
  'el-option': {
    props: ['value', 'label'],
    template: '<option :value="value">{{ label }}</option>'
  },
  'el-dialog': {
    props: ['modelValue'], emits: ['update:modelValue'],
    template: '<div v-if="modelValue" role="dialog"><slot /><slot name="footer" /></div>'
  },
  'el-alert': { props: ['title'], template: '<div role="alert">{{ title }}<slot /></div>' },
  'el-tag': { template: '<span><slot /></span>' },
  'el-input': {
    props: ['modelValue', 'disabled'], emits: ['update:modelValue'],
    template: '<input :value="modelValue" :disabled="disabled" @input="$emit(\'update:modelValue\', $event.target.value)" />'
  },
  'el-progress': { props: ['percentage'], template: '<div class="progress-stub" />' }
}
let wrapper
const state = () => wrapper.vm.$.setupState
const mountPage = async () => {
  wrapper = mount(CloudStorage, { global: { stubs } })
  await flushPromises()
  return state()
}
const click = async id => {
  await wrapper.get(`[data-testid="${id}"]`).trigger('click')
  await flushPromises()
}
const inputPhrase = async value => {
  await wrapper.get('[data-testid="confirmation-input"]').setValue(value)
  await flushPromises()
}
const prepareDialog = async () => {
  await click('open-clear')
  await click('prepare-clear')
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-24T08:00:00Z'))
  vi.resetAllMocks()
  getWopanStoragesReq.mockResolvedValue(ok({ storages: [personal, otherPersonal, family] }))
  getWopanQuotaReq.mockImplementation(id => Promise.resolve(ok(quotaData(id === 2 ? otherPersonal : personal))))
  prepareWopanRecycleReq.mockImplementation(() => Promise.resolve(ok(preparation())))
  clearWopanRecycleReq.mockResolvedValue(ok({ storage_id: 1, status: 'accepted' }))
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  vi.useRealTimers()
})

describe('WoPan discovery and account-scoped quota', () => {
  it('only reads on mount, uses binary units and explicitly warns about account scope', async () => {
    await mountPage()
    expect(getWopanStoragesReq).toHaveBeenCalledTimes(1)
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(1)
    expect(getWopanQuotaReq).toHaveBeenCalledWith(1, { signal: expect.any(AbortSignal) })
    expect(prepareWopanRecycleReq).not.toHaveBeenCalled()
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="total-bytes"]').text()).toContain('1.00 TiB')
    expect(wrapper.get('[data-testid="total-bytes"]').text()).toContain('1099511627776 字节')
    expect(wrapper.text()).toContain('50.00%')
    expect(wrapper.text()).toContain('不是当前挂载子目录的容量')
    expect(wrapper.text()).toContain('回收站占用：未知')
    expect(wrapper.text()).toContain('容量为查询时账号报告值')
    expect(wrapper.text()).toContain('2026')
  })

  it('shows an empty list and can retry discovery without any quota or preparation request', async () => {
    getWopanStoragesReq.mockResolvedValueOnce(ok({ storages: [] }))
    await mountPage()
    expect(wrapper.text()).toContain('暂无沃盘挂载')
    expect(getWopanQuotaReq).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="open-clear"]').exists()).toBe(false)
    await click('reload-storages')
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(1)
    expect(prepareWopanRecycleReq).not.toHaveBeenCalled()
  })

  it('shows the actual rejected storage error and retries visibly', async () => {
    getWopanStoragesReq.mockRejectedValueOnce({ response: { status: 503, data: { msg: '沃盘驱动暂不可用' } } })
    await mountPage()
    expect(wrapper.text()).toContain('沃盘驱动暂不可用')
    expect(getWopanQuotaReq).not.toHaveBeenCalled()
    expect(wrapper.text()).not.toContain('0 B')
    await click('reload-storages')
    expect(wrapper.text()).not.toContain('沃盘驱动暂不可用')
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(1)
  })

  it.each([
    [family, '家庭空间不支持'],
    [{ ...personal, available: false, unsupported_reason: '存储已禁用' }, '存储已禁用']
  ])('does not query or clear unsupported scope/availability: %j', async (storage, reason) => {
    getWopanStoragesReq.mockResolvedValueOnce(ok({ storages: [storage] }))
    const setup = await mountPage()
    expect(wrapper.text()).toContain(reason)
    expect(getWopanQuotaReq).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="open-clear"]').exists()).toBe(false)
    await setup.openRecycleDialog()
    await setup.prepareRecycle()
    await setup.clearRecycle()
    expect(prepareWopanRecycleReq).not.toHaveBeenCalled()
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
  })

  it('hides clearing unless the personal mount explicitly advertises support', async () => {
    getWopanStoragesReq.mockResolvedValueOnce(ok({ storages: [{ ...personal, clear_supported: false, unsupported_reason: '驱动不支持清空' }] }))
    await mountPage()
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-testid="open-clear"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('驱动不支持清空')
  })

  it('shows the real quota rejection instead of zero, with a safe manual retry', async () => {
    getWopanQuotaReq.mockRejectedValueOnce({ response: { status: 502, data: { msg: '沃盘返回容量失败：登录过期' } } })
    await mountPage()
    expect(wrapper.text()).toContain('沃盘返回容量失败：登录过期')
    expect(wrapper.find('[data-testid="total-bytes"]').exists()).toBe(false)
    await click('refresh-quota')
    expect(wrapper.text()).not.toContain('登录过期')
    expect(wrapper.get('[data-testid="total-bytes"]').text()).toContain('1.00 TiB')
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
  })

  it.each([
    { storage_id: 2 }, { mount_path: '/wrong' }, { scope: 'family' }
  ])('rejects quota for a different storage or scope: %j', async mismatch => {
    getWopanQuotaReq.mockResolvedValueOnce(ok(quotaData(personal, mismatch)))
    await mountPage()
    expect(wrapper.text()).toContain('容量响应与当前个人账号挂载不匹配')
    expect(wrapper.find('[data-testid="total-bytes"]').exists()).toBe(false)
  })

  it('keeps exact huge byte strings and handles unknown/zero/invalid ratios without fake zeros', async () => {
    const huge = '18446744073709551615'
    getWopanQuotaReq.mockResolvedValueOnce(ok(quotaData(personal, { total_bytes: huge, used_bytes: '9223372036854775807', available_bytes: null })))
    const setup = await mountPage()
    expect(wrapper.get('[data-testid="total-bytes"]').text()).toContain(`${huge} 字节`)
    expect(wrapper.get('[data-testid="total-bytes"]').text()).toContain('16.00 EiB')
    expect(wrapper.get('[data-testid="available-bytes"]').text()).toContain('未知')
    expect(setup.formatBytes('1073741824')).toBe('1.00 GiB')
    expect(setup.formatBytes('0')).toBe('0 B')
    for (const value of [null, undefined, '', '-1', '1.5', 'garbage', 123]) {
      expect(setup.formatBytes(value)).toBe('未知')
    }
    expect(setup.percentage('9007199254740993', '18014398509481986')).toBe(50)
    expect(setup.percentage('0', '0')).toBeNull()
    expect(setup.percentage('2', '1')).toBeNull()
    expect(setup.percentage(null, '100')).toBeNull()
    expect(setup.formatTime('not-a-date')).toBe('未知')
  })

  it('aborts and ignores old quota across selection changes, including returning to the same ID', async () => {
    const old = deferred()
    getWopanQuotaReq.mockReturnValueOnce(old.promise)
    const setup = await mountPage()
    const oldSignal = getWopanQuotaReq.mock.calls[0][1].signal
    await wrapper.get('[data-testid="storage-select"]').setValue('2')
    await flushPromises()
    expect(oldSignal.aborted).toBe(true)
    expect(setup.quota.storage_id).toBe(2)
    await wrapper.get('[data-testid="storage-select"]').setValue('1')
    await flushPromises()
    old.resolve(ok(quotaData(personal, { total_bytes: '1' })))
    await flushPromises()
    expect(setup.quota.total_bytes).toBe('1099511627776')
    expect(prepareWopanRecycleReq).not.toHaveBeenCalled()
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
  })

  it('does not fall back from family to personal quota after selection', async () => {
    const setup = await mountPage()
    await wrapper.get('[data-testid="storage-select"]').setValue('3')
    await flushPromises()
    expect(setup.quota).toBeNull()
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-testid="open-clear"]').exists()).toBe(false)
  })

  it('translates stable backend errors and unsupported reasons into Chinese', async () => {
    getWopanStoragesReq.mockRejectedValueOnce({ response: { status: 403, data: { msg: 'upstream_admin_required' } } })
    await mountPage()
    expect(wrapper.text()).toContain('上游管理员凭据')
    expect(wrapper.text()).not.toContain('upstream_admin_required')
    getWopanStoragesReq.mockResolvedValueOnce(ok({ storages: [{ ...personal, available: false, clear_supported: false, unsupported_reason: 'storage_credentials_unavailable' }] }))
    await click('reload-storages')
    expect(wrapper.text()).toContain('缺少有效的沃盘账号凭据')
    expect(wrapper.text()).not.toContain('storage_credentials_unavailable')
  })

  it('rejects malformed discovery capabilities rather than enabling actions', async () => {
    getWopanStoragesReq.mockResolvedValueOnce(ok({ storages: [{ ...personal, clear_supported: 'true' }] }))
    await mountPage()
    expect(wrapper.text()).toContain('挂载列表响应无效')
    expect(getWopanQuotaReq).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="open-clear"]').exists()).toBe(false)
  })

  it('aborts discovery on unmount and discards the late response', async () => {
    const pending = deferred()
    getWopanStoragesReq.mockReturnValueOnce(pending.promise)
    const setup = await mountPage()
    const signal = getWopanStoragesReq.mock.calls[0][0].signal
    wrapper.unmount()
    wrapper = undefined
    pending.resolve(ok({ storages: [personal] }))
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(setup.storages).toEqual([])
    expect(getWopanQuotaReq).not.toHaveBeenCalled()
  })

  it('aborts quota on unmount and discards the late response', async () => {
    const pending = deferred()
    getWopanQuotaReq.mockReturnValueOnce(pending.promise)
    const setup = await mountPage()
    const signal = getWopanQuotaReq.mock.calls[0][1].signal
    wrapper.unmount()
    wrapper = undefined
    pending.resolve(ok(quotaData()))
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(setup.quota).toBeNull()
  })
})

describe('WoPan explicit one-use destructive confirmation', () => {
  it('opens warnings without preparing; requires exact typed phrase and never auto-clears', async () => {
    const setup = await mountPage()
    await click('open-clear')
    expect(prepareWopanRecycleReq).not.toHaveBeenCalled()
    expect(wrapper.get('[role="dialog"]').text()).toContain('无法恢复')
    expect(wrapper.get('[role="dialog"]').text()).toContain('整个个人账号、所有挂载')
    expect(wrapper.get('[role="dialog"]').text()).toContain('无法预估可释放空间')
    expect(wrapper.get('[data-testid="confirm-clear"]').element.disabled).toBe(true)
    await setup.clearRecycle()
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
    await click('prepare-clear')
    expect(prepareWopanRecycleReq).toHaveBeenCalledWith(1, { signal: expect.any(AbortSignal) })
    expect(wrapper.text()).toContain('服务端警告')
    for (const wrong of ['', '清空', `${phrase} `, ` ${phrase}`]) {
      await inputPhrase(wrong)
      expect(wrapper.get('[data-testid="confirm-clear"]').element.disabled).toBe(true)
      await setup.clearRecycle()
    }
    await inputPhrase(phrase)
    expect(wrapper.get('[data-testid="confirm-clear"]').element.disabled).toBe(false)
    await vi.advanceTimersByTimeAsync(10000)
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
    await click('confirm-clear')
    expect(clearWopanRecycleReq).toHaveBeenCalledExactlyOnceWith({ storage_id: 1, confirmation_token: 'opaque-one-time-token', confirmation_phrase: phrase })
    expect(setup.prepared).toBeNull()
    expect(setup.confirmationInput).toBe('')
    expect(setup.clearing).toBe(false)
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="clear-notice"]').text()).toContain('已提交清空请求，容量回收可能延迟')
    expect(wrapper.get('[data-testid="clear-notice"]').text()).toContain('不代表清空已完成')
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(1)
    await click('refresh-quota')
    expect(getWopanQuotaReq).toHaveBeenCalledTimes(2)
    expect(clearWopanRecycleReq).toHaveBeenCalledTimes(1)
  })

  it.each([
    { storage_id: 2 },
    { mount_path: '/wrong-mount' },
    { scope: 'family' },
    { confirmation_phrase: '是' },
    { confirmation_token: '' },
    { expires_at: 'invalid' },
    { expires_at: '2026-10-24T07:59:00Z' }
  ])('rejects malicious or unusable preparation: %j', async overrides => {
    prepareWopanRecycleReq.mockResolvedValueOnce(ok(preparation(overrides)))
    const setup = await mountPage()
    await prepareDialog()
    expect(setup.prepared).toBeNull()
    expect(wrapper.get('[data-testid="dialog-error"]').text()).toContain('确认凭证无效')
    expect(wrapper.get('[data-testid="confirm-clear"]').element.disabled).toBe(true)
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
  })

  it('shows preparation errors and can retry only after another explicit click', async () => {
    prepareWopanRecycleReq.mockRejectedValueOnce({ response: { status: 503, data: { msg: '确认服务暂不可用' } } })
    await mountPage()
    await prepareDialog()
    expect(wrapper.get('[data-testid="dialog-error"]').text()).toContain('确认服务暂不可用')
    await vi.advanceTimersByTimeAsync(10000)
    expect(prepareWopanRecycleReq).toHaveBeenCalledTimes(1)
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
    await click('prepare-clear')
    expect(state().prepared.confirmation_token).toBe('opaque-one-time-token')
  })

  it('consumes the token on clear failure, displays the backend error, and never retries', async () => {
    clearWopanRecycleReq.mockRejectedValueOnce({ response: { status: 502, data: { msg: '沃盘拒绝清空请求' } } })
    const setup = await mountPage()
    await prepareDialog()
    await inputPhrase(phrase)
    await click('confirm-clear')
    expect(wrapper.get('[data-testid="dialog-error"]').text()).toContain('沃盘拒绝清空请求')
    expect(wrapper.get('[data-testid="dialog-error"]').text()).toContain('不会自动重试')
    expect(setup.prepared).toBeNull()
    expect(setup.confirmationInput).toBe('')
    expect(wrapper.get('[data-testid="confirm-clear"]').element.disabled).toBe(true)
    await setup.clearRecycle()
    await vi.advanceTimersByTimeAsync(120000)
    expect(clearWopanRecycleReq).toHaveBeenCalledTimes(1)
    await click('prepare-clear')
    expect(prepareWopanRecycleReq).toHaveBeenCalledTimes(2)
  })

  it('guards duplicate preparation and clearing while requests are working', async () => {
    const prep = deferred()
    prepareWopanRecycleReq.mockReturnValueOnce(prep.promise)
    const setup = await mountPage()
    await click('open-clear')
    await click('prepare-clear')
    expect(wrapper.get('[data-testid="storage-select"]').element.disabled).toBe(true)
    await setup.prepareRecycle()
    expect(prepareWopanRecycleReq).toHaveBeenCalledTimes(1)
    prep.resolve(ok(preparation()))
    await flushPromises()
    await inputPhrase(phrase)
    const clear = deferred()
    clearWopanRecycleReq.mockReturnValueOnce(clear.promise)
    await click('confirm-clear')
    expect(setup.prepared).toBeNull()
    expect(wrapper.get('[data-testid="cancel-clear"]').element.disabled).toBe(true)
    expect(wrapper.get('[data-testid="refresh-quota"]').element.disabled).toBe(true)
    await setup.clearRecycle()
    await setup.closeRecycleDialog()
    expect(setup.dialogVisible).toBe(true)
    expect(clearWopanRecycleReq).toHaveBeenCalledTimes(1)
    clear.resolve(ok({ status: 'accepted' }))
    await flushPromises()
    expect(setup.clearing).toBe(false)
  })

  it('invalidates the token on dialog cancellation, selection changes, and expiry', async () => {
    const setup = await mountPage()
    await prepareDialog()
    await inputPhrase(phrase)
    await click('cancel-clear')
    expect(setup.prepared).toBeNull()
    expect(setup.confirmationInput).toBe('')
    await prepareDialog()
    await wrapper.get('[data-testid="storage-select"]').setValue('2')
    await flushPromises()
    expect(setup.prepared).toBeNull()
    expect(setup.dialogVisible).toBe(false)
    await wrapper.get('[data-testid="storage-select"]').setValue('1')
    await flushPromises()
    await prepareDialog()
    await inputPhrase(phrase)
    await vi.advanceTimersByTimeAsync(60000)
    expect(setup.prepared).toBeNull()
    expect(wrapper.get('[data-testid="dialog-error"]').text()).toContain('确认凭证已过期')
    await setup.clearRecycle()
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
  })

  it('discards preparation that resolves after closing the dialog', async () => {
    const pending = deferred()
    prepareWopanRecycleReq.mockReturnValueOnce(pending.promise)
    const setup = await mountPage()
    await prepareDialog()
    const signal = prepareWopanRecycleReq.mock.calls[0][1].signal
    await click('cancel-clear')
    pending.resolve(ok(preparation()))
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(setup.prepared).toBeNull()
    expect(setup.dialogVisible).toBe(false)
    expect(clearWopanRecycleReq).not.toHaveBeenCalled()
  })

  it('aborts preparation on unmount and never keeps a late credential or timer', async () => {
    const pending = deferred()
    prepareWopanRecycleReq.mockReturnValueOnce(pending.promise)
    const setup = await mountPage()
    await prepareDialog()
    const signal = prepareWopanRecycleReq.mock.calls[0][1].signal
    wrapper.unmount()
    wrapper = undefined
    pending.resolve(ok(preparation()))
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(setup.prepared).toBeNull()
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each([{ status: 'unknown' }, { status: 'accepted', storage_id: 999 }, { status: 'accepted', mount_path: '/wrong-mount' }])('does not claim success for an unverified result: %j', async result => {
    clearWopanRecycleReq.mockResolvedValueOnce(ok(result))
    await mountPage()
    await prepareDialog()
    await inputPhrase(phrase)
    await click('confirm-clear')
    expect(wrapper.get('[data-testid="dialog-error"]').text()).toContain('结果无法确认')
    expect(wrapper.find('[data-testid="clear-notice"]').exists()).toBe(false)
    expect(state().prepared).toBeNull()
  })
})
