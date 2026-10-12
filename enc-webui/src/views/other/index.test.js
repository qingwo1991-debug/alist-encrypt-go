import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import OtherPage from './index.vue'
import { getPlaybackStatsReq } from '@/api/user'

vi.mock('@/api/user', () => ({
  clearPlaybackStatsReq: vi.fn(),
  getBuildInfoReq: vi.fn().mockResolvedValue({ data: {} }),
  getStatsReq: vi.fn().mockResolvedValue({ data: {} }),
  getPlaybackStatsReq: vi.fn()
}))

let wrapper
const showPage = async rows => {
  getPlaybackStatsReq.mockResolvedValue({ data: { playbacks: rows } })
  wrapper = mount(OtherPage, { global: { stubs: {
    'el-button': true,
    'el-tabs': { template: '<div><slot /></div>' },
    'el-tab-pane': { template: '<div><slot /></div>' },
    'el-table': { template: '<div><slot /></div>' },
    'el-table-column': true
  } } })
  await flushPromises()
}

beforeEach(() => {
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
})
afterEach(() => {
  wrapper?.unmount()
  vi.restoreAllMocks()
})

describe('playback metrics page rendered semantics', () => {
  it('renders body-first-byte quantiles rather than response-header quantiles', async () => {
    await showPage([
      { played_at: 1, header_latency_ms: 999 },
      { played_at: '2026-01-01T00:00:02Z', first_byte_latency_ms: 0, header_latency_ms: 500 },
      { played_at: 3, first_byte_latency_ms: 20 },
      { played_at: 4, first_byte_latency_ms: 40 },
      { played_at: 5, first_byte_latency_ms: 100 }
    ])
    expect(wrapper.text()).toContain('服务端正文首字节')
    expect(wrapper.text()).toContain('first_byte_latency_ms · p50 40ms · p95 100ms')
    expect(wrapper.text()).toContain('均非播放器真实首帧')
    expect(wrapper.findAllComponents({ name: 'el-table-column' }).length).toBeGreaterThan(0)
    const columns = wrapper.findAll('el-table-column-stub').map(column => column.attributes('label'))
    expect(columns).toContain('正文首字节ms')
    expect(columns).toContain('上游响应头ms')
    expect(wrapper.text()).not.toContain('undefined')
  })

  it('keeps historical header-only rows unknown for new metric', async () => {
    await showPage([{ played_at: 1, header_latency_ms: 999 }])
    expect(wrapper.text()).toContain('first_byte_latency_ms · p50 -ms · p95 -ms')
    expect(wrapper.vm.$.setupState.latencySeries).toEqual([])
  })
})
