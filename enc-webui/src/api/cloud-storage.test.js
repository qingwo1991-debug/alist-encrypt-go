import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/utils/axios-req', () => ({ default: vi.fn() }))
import axiosReq from '@/utils/axios-req'
import { clearWopanRecycleReq, getWopanQuotaReq, getWopanStoragesReq, prepareWopanRecycleReq } from './cloud-storage'

beforeEach(() => axiosReq.mockReset())

describe('WoPan local admin transport', () => {
  it('reads discovery using axiosReq and preserves the actual code-zero response', async () => {
    const response = { code: 0, data: { storages: [] } }
    const controller = new AbortController()
    axiosReq.mockResolvedValueOnce(response)
    await expect(getWopanStoragesReq({ signal: controller.signal })).resolves.toBe(response)
    expect(axiosReq).toHaveBeenCalledExactlyOnceWith({
      url: '/enc-api/wopan/storages', method: 'get', data: undefined,
      signal: controller.signal, timeout: 20000, reqLoading: false, isNotTipErrorMsg: true, skipForbiddenAuthReset: true
    })
  })

  it('passes quota storage_id as data so the shared GET interceptor builds query parameters', async () => {
    const controller = new AbortController()
    await getWopanQuotaReq(42, { signal: controller.signal })
    expect(axiosReq).toHaveBeenCalledExactlyOnceWith({
      url: '/enc-api/wopan/quota', method: 'get', data: { storage_id: 42 },
      signal: controller.signal, timeout: 20000, reqLoading: false, isNotTipErrorMsg: true, skipForbiddenAuthReset: true
    })
  })

  it('prepares only the selected storage, without typed text or credentials', async () => {
    await prepareWopanRecycleReq(9)
    expect(axiosReq).toHaveBeenCalledExactlyOnceWith({
      url: '/enc-api/wopan/recycle/prepare', method: 'post', data: { storage_id: 9 },
      signal: undefined, timeout: 20000, reqLoading: false, isNotTipErrorMsg: true, skipForbiddenAuthReset: true
    })
  })

  it('submits exactly the one-use confirmation body and never retries rejection', async () => {
    const error = { response: { status: 503, data: { msg: '服务不可用' } } }
    axiosReq.mockRejectedValueOnce(error)
    const body = { storage_id: 4, confirmation_token: 'opaque-token', confirmation_phrase: '清空个人账号全部回收站' }
    await expect(clearWopanRecycleReq({ ...body, extra: 'must-not-be-sent' })).rejects.toBe(error)
    expect(axiosReq).toHaveBeenCalledExactlyOnceWith({
      url: '/enc-api/wopan/recycle/clear', method: 'post', data: body,
      signal: undefined, timeout: 20000, reqLoading: false, isNotTipErrorMsg: true, skipForbiddenAuthReset: true
    })
  })
})
