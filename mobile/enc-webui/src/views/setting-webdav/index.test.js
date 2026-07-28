import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/user', () => ({
  delWebdavConfigReq: vi.fn(),
  getWebdavConfigReq: vi.fn(),
  saveWebdavConfigReq: vi.fn(),
  updateWebdavConfigReq: vi.fn()
}))
vi.mock('element-plus', () => {
  const ElMessage = vi.fn()
  ElMessage.error = vi.fn()
  return {
    ElMessage,
    ElMessageBox: { confirm: vi.fn() }
  }
})
vi.mock('@element-plus/icons-vue', () => ({ Delete: {} }))

import {
  delWebdavConfigReq,
  getWebdavConfigReq,
  saveWebdavConfigReq,
  updateWebdavConfigReq
} from '@/api/user'
import { ElMessage, ElMessageBox } from 'element-plus'
import WebdavSettings from './index.vue'

const mountSettings = () =>
  mount(WebdavSettings, {
    global: {
      stubs: {
        'el-button': true,
        'el-switch': true,
        'el-input': true,
        'el-form-item': true,
        'el-form': true,
        'el-radio': true,
        'el-radio-group': true,
        'el-dialog': true
      }
    }
  })

describe('WebDAV form state', () => {
  beforeEach(() => {
    getWebdavConfigReq.mockReset()
    getWebdavConfigReq.mockResolvedValue({ data: [] })
    saveWebdavConfigReq.mockReset()
    saveWebdavConfigReq.mockResolvedValue({ data: [], msg: 'saved' })
    updateWebdavConfigReq.mockReset()
    updateWebdavConfigReq.mockResolvedValue({ data: [] })
    delWebdavConfigReq.mockReset()
    ElMessage.error.mockReset()
    ElMessageBox.confirm.mockReset()
  })

  it('removes the edited id before saving a new configuration', async () => {
    const wrapper = mountSettings()
    await flushPromises()
    const setup = wrapper.vm.$.setupState

    setup.editConfig({ id: 42, name: 'existing', passwdList: [] })
    setup.addConfig()
    await setup.saveWebdavConfig()

    expect(updateWebdavConfigReq).not.toHaveBeenCalled()
    expect(saveWebdavConfigReq).toHaveBeenCalledTimes(1)
    expect(saveWebdavConfigReq.mock.calls[0][0].id).toBeUndefined()
  })

  it('treats confirmation cancellation as a normal no-op', async () => {
    ElMessageBox.confirm.mockRejectedValue('cancel')
    const wrapper = mountSettings()
    await flushPromises()

    await expect(wrapper.vm.$.setupState.delWebdavConfig(42)).resolves.toBeUndefined()
    expect(delWebdavConfigReq).not.toHaveBeenCalled()
  })

  it('creates password rules blank and disabled', async () => {
    const wrapper = mountSettings()
    await flushPromises()
    const setup = wrapper.vm.$.setupState

    setup.addConfig()
    setup.addPasswd()
    const rule = setup.configFormTemp.passwdList.at(-1)

    expect(rule.password).toBe('')
    expect(rule.enable).toBe(false)
  })

  it('refuses to save an enabled rule without a password', async () => {
    const wrapper = mountSettings()
    await flushPromises()
    const setup = wrapper.vm.$.setupState

    setup.addConfig()
    setup.configFormTemp.passwdList[0].enable = true
    setup.configFormTemp.passwdList[0].password = '   '
    await setup.saveWebdavConfig()

    expect(saveWebdavConfigReq).not.toHaveBeenCalled()
    expect(updateWebdavConfigReq).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('已启用的密码规则必须填写密码')
  })

  it('rolls back quick enable when an enabled password rule is blank', async () => {
    const wrapper = mountSettings()
    await flushPromises()
    const config = { enable: true, passwdList: [{ enable: true, password: '   ' }] }

    await wrapper.vm.$.setupState.updateWebdavConfig(config, true)

    expect(config.enable).toBe(false)
    expect(updateWebdavConfigReq).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('已启用的密码规则必须填写密码')
  })

  it('rolls back quick enable when the update request rejects', async () => {
    updateWebdavConfigReq.mockRejectedValueOnce(new Error('save failed'))
    const wrapper = mountSettings()
    await flushPromises()
    const config = { enable: true, passwdList: [{ enable: true, password: 'strong password' }] }

    await wrapper.vm.$.setupState.updateWebdavConfig(config, true)

    expect(config.enable).toBe(false)
    expect(updateWebdavConfigReq).toHaveBeenCalledTimes(1)
  })
})
