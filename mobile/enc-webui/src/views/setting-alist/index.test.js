import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/user', () => ({
  decodeFoldNameReq: vi.fn(),
  encodeFoldNameReq: vi.fn(),
  getAlistConfigReq: vi.fn(),
  saveAlistConfigReq: vi.fn()
}))
vi.mock('element-plus', () => {
  const ElMessage = vi.fn()
  ElMessage.error = vi.fn()
  ElMessage.success = vi.fn()
  return { ElMessage }
})
vi.mock('@element-plus/icons-vue', () => ({ Delete: {} }))

import { getAlistConfigReq, saveAlistConfigReq } from '@/api/user'
import { ElMessage } from 'element-plus'
import AlistSettings from './index.vue'

const elementStubs = {
  'el-button': true,
  'el-collapse': true,
  'el-collapse-item': true,
  'el-dialog': true,
  'el-form': true,
  'el-form-item': true,
  'el-input': true,
  'el-radio': true,
  'el-radio-group': true,
  'el-switch': true,
  'el-tab-pane': true,
  'el-tabs': true
}

let wrapper

const mountSettings = async () => {
  wrapper = mount(AlistSettings, { global: { stubs: elementStubs } })
  await flushPromises()
  return wrapper.vm.$.setupState
}

describe('Alist password rule defaults', () => {
  beforeEach(() => {
    getAlistConfigReq.mockReset()
    getAlistConfigReq.mockResolvedValue({ data: { passwdList: [] } })
    saveAlistConfigReq.mockReset()
    saveAlistConfigReq.mockResolvedValue({ msg: 'saved' })
    ElMessage.error.mockReset()
    ElMessage.success.mockReset()
  })

  afterEach(() => {
    wrapper?.unmount()
    wrapper = undefined
  })

  it('creates new rules blank and disabled', async () => {
    const setup = await mountSettings()

    setup.addPasswd()
    const rule = setup.alistConfigForm.passwdList.at(-1)

    expect(rule.password).toBe('')
    expect(rule.enable).toBe(false)
  })

  it('does not persist an enabled rule with a blank password', async () => {
    const setup = await mountSettings()
    setup.addPasswd()
    setup.alistConfigForm.passwdList[0].enable = true
    setup.alistConfigForm.passwdList[0].password = '   '

    await setup.saveAlistConfig()

    expect(saveAlistConfigReq).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('已启用的密码规则必须填写密码')
  })

  it('does not report success when Alist save rejects', async () => {
    saveAlistConfigReq.mockRejectedValueOnce(new Error('save failed'))
    const setup = await mountSettings()

    await setup.saveAlistConfig()

    expect(saveAlistConfigReq).toHaveBeenCalledTimes(1)
    expect(ElMessage.success).not.toHaveBeenCalled()
  })
})
