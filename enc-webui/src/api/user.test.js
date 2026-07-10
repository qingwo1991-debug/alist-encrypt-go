import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/utils/axios-req', () => ({
  default: vi.fn()
}))

import axiosReq from '@/utils/axios-req'
import { userInfoReq } from './user'

describe('userInfoReq', () => {
  beforeEach(() => {
    axiosReq.mockReset()
  })

  it('returns the user payload', async () => {
    axiosReq.mockResolvedValue({ data: { username: 'admin' } })

    await expect(userInfoReq()).resolves.toEqual({ username: 'admin' })
  })

  it('propagates an expired-session rejection', async () => {
    const unauthorized = new Error('Request failed with status code 401')
    axiosReq.mockRejectedValue(unauthorized)

    await expect(userInfoReq()).rejects.toBe(unauthorized)
  })
})
