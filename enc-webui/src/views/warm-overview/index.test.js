import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/user', () => ({ getStatsReq: vi.fn() }))
import { getStatsReq } from '@/api/user'
import WarmOverview from './index.vue'

const deferred = () => {
  let resolve
  const promise = new Promise(res => { resolve = res })
  return { promise, resolve }
}
const states = count => Array.from({ length: count }, (_, i) => ({ display_path: `/${i}`, state: i % 2 ? 'ready' : 'stale' }))
let wrapper
let hidden
const mountPage = async () => {
  wrapper = mount(WarmOverview, {
    global: { stubs: {
      'el-button': true, 'el-select': true, 'el-option': true,
      'el-table': { props: ['data'], template: '<div class="table-stub" />' },
      'el-table-column': true, 'el-tag': true, 'el-pagination': true
    } }
  })
  await flushPromises()
  return wrapper.vm.$.setupState
}

describe('warm overview bounded rendering and lifecycle', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    hidden = false
    vi.spyOn(document, 'hidden', 'get').mockImplementation(() => hidden)
    getStatsReq.mockReset()
    getStatsReq.mockResolvedValue({ data: { probe_scheduler: { current_warm_states: states(10000) } } })
  })
  afterEach(() => {
    wrapper?.unmount()
    wrapper = undefined
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  it('passes only one page to the table and resets/clamps pages', async () => {
    const setup = await mountPage()
    expect(setup.paginatedWarm).toHaveLength(50)
    expect(wrapper.findComponent('.table-stub').props('data')).toHaveLength(50)
    setup.currentPage = 200
    setup.stateFilter = 'ready'
    await flushPromises()
    expect(setup.currentPage).toBe(1)
    expect(setup.filteredWarm).toHaveLength(5000)
    setup.currentPage = 100
    getStatsReq.mockResolvedValueOnce({ data: { probe_scheduler: { current_warm_states: states(120) } } })
    await setup.loadAll()
    await flushPromises()
    expect(setup.currentPage).toBe(2)
    expect(setup.paginatedWarm).toHaveLength(10)
    expect(wrapper.text()).toContain('非历史总数')
  })

  it('ignores late initial data and never schedules after unmount', async () => {
    const request = deferred()
    getStatsReq.mockReturnValueOnce(request.promise)
    const setup = await mountPage()
    const signal = getStatsReq.mock.calls[0][0].signal
    wrapper.unmount()
    wrapper = undefined
    request.resolve({ data: { probe_scheduler: { unique_warmed_files: 99 } } })
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(setup.sched.unique_warmed_files).toBeUndefined()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('shares a slow request with manual refresh and schedules only after completion', async () => {
    const setup = await mountPage()
    const request = deferred()
    getStatsReq.mockReturnValueOnce(request.promise)
    await vi.advanceTimersByTimeAsync(8000)
    const manual = setup.loadAll()
    await vi.advanceTimersByTimeAsync(24000)
    expect(getStatsReq).toHaveBeenCalledTimes(2)
    request.resolve({ data: {} })
    await manual
    await flushPromises()
    expect(vi.getTimerCount()).toBe(1)
  })

  it('pauses all requests while hidden and resumes immediately on visibility', async () => {
    const setup = await mountPage()
    hidden = true
    await vi.advanceTimersByTimeAsync(24000)
    await setup.loadAll()
    expect(getStatsReq).toHaveBeenCalledTimes(1)
    hidden = false
    document.dispatchEvent(new Event('visibilitychange'))
    await flushPromises()
    expect(getStatsReq).toHaveBeenCalledTimes(2)
    wrapper.unmount()
    wrapper = undefined
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.advanceTimersByTimeAsync(8000)
    expect(getStatsReq).toHaveBeenCalledTimes(2)
  })

  it('recovers from failed requests without stopping polls', async () => {
    getStatsReq.mockRejectedValueOnce(new Error('offline'))
    await mountPage()
    await vi.advanceTimersByTimeAsync(8000)
    expect(getStatsReq).toHaveBeenCalledTimes(2)
  })
})
