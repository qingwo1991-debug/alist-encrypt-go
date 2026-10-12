// Missing/invalid metrics are unknown, not zero. An explicit numeric zero is valid.
// The server must omit unknown values (or supply validity metadata); the UI cannot
// distinguish a measured zero from a legacy sentinel zero in the same field.
export const metricValue = (row, field) => {
  const value = row?.[field]
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

export const formatLatency = (row, field) => {
  const value = metricValue(row, field)
  return value === null ? '-' : String(Math.round(value))
}

// Root exports RFC3339 time.Time; mobile exports Unix seconds.
export const playbackTimestamp = value => {
  const timestamp = typeof value === 'number' ? value * 1000 : typeof value === 'string' ? Date.parse(value) : Number.NaN
  return Number.isFinite(timestamp) ? timestamp : null
}

export const latencySeriesFor = (rows, field = 'first_byte_latency_ms') => (rows || [])
  .filter(row => metricValue(row, field) !== null && playbackTimestamp(row.played_at) !== null)
  .slice()
  .sort((a, b) => playbackTimestamp(a.played_at) - playbackTimestamp(b.played_at))
  .slice(-200)
  .map(row => ({ t: new Date(playbackTimestamp(row.played_at)), v: metricValue(row, field) }))

// Preserve the existing nearest-index quantile convention.
export const percentile = (values, q) => {
  const sorted = values.filter(value => typeof value === 'number' && Number.isFinite(value) && value >= 0).sort((a, b) => a - b)
  if (!sorted.length) return '-'
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.round(q * (sorted.length - 1))))
  return Math.round(sorted[idx])
}
