import { describe, expect, it } from 'vitest'
import { formatLatency, latencySeriesFor, percentile } from './playback-metrics'

describe('server body-first-byte metrics', () => {
  it('never substitutes historical headers or missing fields with zero', () => {
    const rows = [
      { played_at: 1, header_latency_ms: 900 },
      { played_at: 2, first_byte_latency_ms: null },
      { played_at: 3, first_byte_latency_ms: 0 },
      { played_at: 4, first_byte_latency_ms: 20 },
      { played_at: 5, first_byte_latency_ms: 40 },
      { played_at: 6, first_byte_latency_ms: 100 }
    ]
    const values = latencySeriesFor(rows).map(point => point.v)
    expect(values).toEqual([0, 20, 40, 100])
    expect(percentile(values, 0.5)).toBe(40)
    expect(percentile(values, 0.95)).toBe(100)
    expect(formatLatency(rows[0], 'first_byte_latency_ms')).toBe('-')
    expect(formatLatency(rows[0], 'header_latency_ms')).toBe('900')
    expect(formatLatency(rows[2], 'first_byte_latency_ms')).toBe('0')
  })

  it('filters invalid values without producing undefined', () => {
    const values = [undefined, null, -1, NaN, Infinity, '20']
    expect(latencySeriesFor(values.map(value => ({ played_at: 1, first_byte_latency_ms: value })))).toEqual([])
    expect(percentile(values, 0.95)).toBe('-')
    expect(formatLatency({}, 'first_byte_latency_ms')).toBe('-')
  })

  it('accepts root RFC3339 timestamps and rejects invalid/missing timestamps', () => {
    const series = latencySeriesFor([
      { played_at: '2026-01-01T00:00:02Z', first_byte_latency_ms: 20 },
      { played_at: '2026-01-01T00:00:01Z', first_byte_latency_ms: 10 },
      { played_at: 'invalid', first_byte_latency_ms: 40 },
      { first_byte_latency_ms: 50 }
    ])
    expect(series.map(point => point.v)).toEqual([10, 20])
    expect(series[0].t.toISOString()).toBe('2026-01-01T00:00:01.000Z')
  })

  it('sorts unix-second timestamps and limits samples without mutating input', () => {
    const rows = Array.from({ length: 201 }, (_, i) => ({ played_at: 201 - i, first_byte_latency_ms: i }))
    const series = latencySeriesFor(rows)
    expect(series).toHaveLength(200)
    expect(series[0].t.getTime()).toBe(2000)
    expect(series.at(-1).t.getTime()).toBe(201000)
    expect(rows[0].played_at).toBe(201)
  })
})
