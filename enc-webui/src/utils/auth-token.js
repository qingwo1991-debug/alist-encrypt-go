// JWT expiry can be checked locally before the first protected request. This
// is not a security decision (the server still validates every token); it only
// avoids a guaranteed 401 when a persisted browser session has expired.
export const isJWTExpired = (rawToken, nowMs = Date.now(), skewMs = 5000) => {
  const token = String(rawToken || '').replace(/^Bearer\s+/i, '').trim()
  const parts = token.split('.')
  if (parts.length !== 3) return true

  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, '=')
    const decoded = atob(padded)
    const match = decoded.match(/"exp"\s*:\s*(\d+)/)
    if (!match) return true
    return Number(match[1]) * 1000 <= nowMs + skewMs
  } catch {
    return true
  }
}
