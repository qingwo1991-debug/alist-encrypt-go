import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/router', () => ({
  default: {
    beforeEach: vi.fn(),
    afterEach: vi.fn()
  }
}))
vi.mock('@/hooks/use-permission', () => ({
  filterAsyncRouter: vi.fn(),
  progressClose: vi.fn(),
  progressStart: vi.fn()
}))
vi.mock('@/store/basic', () => ({ useBasicStore: vi.fn() }))
vi.mock('@/api/user', () => ({ userInfoReq: vi.fn() }))
vi.mock('@/hooks/use-common', () => ({ langTitle: () => 'Test' }))

import router from '@/router'
import { progressClose } from '@/hooks/use-permission'
import { useBasicStore } from '@/store/basic'
import { userInfoReq } from '@/api/user'
import './permission'

const registeredGuard = router.beforeEach.mock.calls[0][0]

describe('route permission guard', () => {
  const store = {
    token: 'expired-token',
    getUserInfo: false,
    resetState: vi.fn(),
    setFilterAsyncRoutes: vi.fn(),
    setUserInfo: vi.fn()
  }

  beforeEach(() => {
    store.resetState.mockReset()
    useBasicStore.mockReset()
    useBasicStore.mockReturnValue(store)
    userInfoReq.mockReset()
    progressClose.mockReset()
  })

  it('settles with a login redirect when loading user info rejects', async () => {
    const unauthorized = new Error('Request failed with status code 401')
    unauthorized.response = { status: 401 }
    userInfoReq.mockRejectedValue(unauthorized)
    await expect(registeredGuard({ path: '/setting', meta: {} })).resolves.toBe('/login?redirect=/setting')
    expect(store.resetState).toHaveBeenCalledTimes(1)
    expect(progressClose).toHaveBeenCalledTimes(1)
  })
})
