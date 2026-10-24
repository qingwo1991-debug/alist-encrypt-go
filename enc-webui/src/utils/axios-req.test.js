import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('element-plus', () => ({
  ElLoading: { service: vi.fn() },
  ElMessage: { error: vi.fn() }
}))

vi.mock('@/store/basic', () => ({
  useBasicStore: vi.fn()
}))

import { ElLoading, ElMessage } from 'element-plus'
import { useBasicStore } from '@/store/basic'
import axiosReq from './axios-req'

const deferred = () => {
  let resolve
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

const adapterResponse = (config, data) => ({
  data: { code: 0, data },
  status: 200,
  statusText: 'OK',
  headers: { 'content-type': 'application/json' },
  config,
  request: {}
})

describe('axiosReq request cleanup', () => {
  const store = {
    token: 'test-token',
    axiosPromiseArr: [],
    resetStateAndToLogin: vi.fn()
  }

  beforeEach(() => {
    vi.useFakeTimers()
    store.axiosPromiseArr.splice(0)
    store.resetStateAndToLogin.mockReset()
    useBasicStore.mockReset()
    useBasicStore.mockReturnValue(store)
    ElLoading.service.mockReset()
    ElMessage.error.mockReset()
  })
  afterEach(() => {
    vi.runOnlyPendingTimers()
    vi.useRealTimers()
  })

  it.each([
    [403, true, false],
    [403, undefined, true],
    [401, true, true],
    [401, undefined, true]
  ])('handles HTTP %s with skipForbiddenAuthReset=%s (reset=%s)', async (status, skipForbiddenAuthReset, resetExpected) => {
    const failure = new Error('permission denied')
    const request = axiosReq({
      url: '/enc-api/wopan/storages',
      method: 'get',
      reqLoading: false,
      isNotTipErrorMsg: true,
      skipForbiddenAuthReset,
      adapter: async config => {
        failure.config = config
        failure.response = { status, data: { msg: 'upstream_admin_required' } }
        throw failure
      }
    })
    await expect(request).rejects.toBe(failure)
    expect(store.resetStateAndToLogin).toHaveBeenCalledTimes(resetExpected ? 1 : 0)
    expect(store.axiosPromiseArr).toEqual([])
  })

  it.each([
    [403, true, false],
    [403, undefined, true],
    [401, true, true],
    [401, undefined, true]
  ])('handles envelope code %s with skipForbiddenAuthReset=%s (reset=%s)', async (code, skipForbiddenAuthReset, resetExpected) => {
    const request = axiosReq({
      url: '/enc-api/wopan/storages',
      method: 'get',
      reqLoading: false,
      isNotTipErrorMsg: true,
      skipForbiddenAuthReset,
      adapter: async config => ({
        ...adapterResponse(config, null),
        data: { code, msg: 'upstream_admin_required' }
      })
    })
    await expect(request).rejects.toBe('upstream_admin_required')
    expect(store.resetStateAndToLogin).toHaveBeenCalledTimes(resetExpected ? 1 : 0)
    expect(store.axiosPromiseArr).toEqual([])
  })

  it('cleans up the matching request when concurrent responses finish out of order', async () => {
    const firstLoading = { close: vi.fn() }
    const secondLoading = { close: vi.fn() }
    ElLoading.service.mockReturnValueOnce(firstLoading).mockReturnValueOnce(secondLoading)
    const firstGate = deferred()
    const secondGate = deferred()

    const firstRequest = axiosReq({
      url: '/first',
      method: 'get',
      adapter: async (config) => {
        await firstGate.promise
        return adapterResponse(config, 'first')
      }
    })
    const secondRequest = axiosReq({
      url: '/second',
      method: 'get',
      adapter: async (config) => {
        await secondGate.promise
        return adapterResponse(config, 'second')
      }
    })

    await Promise.resolve()
    await Promise.resolve()
    expect(store.axiosPromiseArr.map(({ url }) => url)).toEqual(['/first', '/second'])

    secondGate.resolve()
    await expect(secondRequest).resolves.toEqual({ code: 0, data: 'second' })
    expect(secondLoading.close).toHaveBeenCalledTimes(1)
    expect(firstLoading.close).not.toHaveBeenCalled()
    expect(store.axiosPromiseArr.map(({ url }) => url)).toEqual(['/first'])

    firstGate.resolve()
    await expect(firstRequest).resolves.toEqual({ code: 0, data: 'first' })
    expect(firstLoading.close).toHaveBeenCalledTimes(1)
    expect(store.axiosPromiseArr).toEqual([])
  })

  it('also closes and removes request state after a transport failure', async () => {
    const loading = { close: vi.fn() }
    ElLoading.service.mockReturnValueOnce(loading)
    const failure = new Error('network failed')

    const request = axiosReq({
      url: '/failure',
      method: 'post',
      adapter: async (config) => {
        failure.config = config
        throw failure
      }
    })

    await expect(request).rejects.toBe(failure)
    expect(loading.close).toHaveBeenCalledTimes(1)
    expect(store.axiosPromiseArr).toEqual([])
  })
})
