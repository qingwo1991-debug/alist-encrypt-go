import { beforeEach, describe, expect, it, vi } from 'vitest'

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
    store.axiosPromiseArr.splice(0)
    store.resetStateAndToLogin.mockReset()
    useBasicStore.mockReset()
    useBasicStore.mockReturnValue(store)
    ElLoading.service.mockReset()
    ElMessage.error.mockReset()
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
