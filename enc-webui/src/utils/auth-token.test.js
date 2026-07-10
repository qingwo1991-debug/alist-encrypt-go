import { describe, expect, it } from 'vitest'

import { isJWTExpired } from './auth-token'

const tokenWithExpiry = (exp) => {
  const payload = btoa(JSON.stringify({ sub: 'admin', exp }))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
  return `header.${payload}.signature`
}

describe('isJWTExpired', () => {
  it('detects an expired persisted session', () => {
    expect(isJWTExpired(tokenWithExpiry(100), 101000, 0)).toBe(true)
  })

  it('keeps a current token and accepts a Bearer prefix', () => {
    expect(isJWTExpired(`Bearer ${tokenWithExpiry(200)}`, 100000, 0)).toBe(false)
  })

  it('fails closed for malformed persisted values', () => {
    expect(isJWTExpired('old-local-storage-token')).toBe(true)
  })
})
