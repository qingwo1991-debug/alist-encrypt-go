import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/store/pageStore', () => ({ usePageStore: vi.fn() }))
vi.mock('@/api/user', () => ({ encryptFileReq: vi.fn() }))
vi.mock('element-plus', () => ({
  ElMessage: {
    error: vi.fn(),
    success: vi.fn()
  }
}))

import { encryptFileReq } from '@/api/user'
import { usePageStore } from '@/store/pageStore'
import { ElMessage } from 'element-plus'
import EncryptLocal from './index.vue'

const setFolderInfo = vi.fn()

const mountEncryptLocal = () =>
  mount(EncryptLocal, {
    global: {
      stubs: {
        'el-form': true,
        'el-form-item': true,
        'el-radio-group': true,
        'el-radio': true,
        'el-input': true,
        'el-switch': true,
        'el-button': true
      }
    }
  })

describe('local encryption password safety', () => {
  beforeEach(() => {
    setFolderInfo.mockReset()
    encryptFileReq.mockReset()
    ElMessage.error.mockReset()
    ElMessage.success.mockReset()
    usePageStore.mockReset()
    usePageStore.mockReturnValue({
      folderInfo: { folderPath: '/input', outPath: '/output' },
      setFolderInfo
    })
  })

  it('starts without a default password', () => {
    const setup = mountEncryptLocal().vm.$.setupState

    expect(setup.folderForm.password).toBe('')
  })

  it.each(['enc', 'dec'])('blocks a blank password for %s operations', (operation) => {
    const setup = mountEncryptLocal().vm.$.setupState
    setup.folderForm.operation = operation
    setup.folderForm.password = '   '

    setup.encryptFile()

    expect(encryptFileReq).not.toHaveBeenCalled()
    expect(setFolderInfo).not.toHaveBeenCalled()
    expect(ElMessage.error).toHaveBeenCalledWith('请输入加解密密码')
  })

  it('persists only paths after a valid password is supplied', async () => {
    encryptFileReq.mockResolvedValue({ msg: 'done' })
    const setup = mountEncryptLocal().vm.$.setupState
    setup.folderForm.password = 'strong password'

    await setup.encryptFile()

    expect(setFolderInfo).toHaveBeenCalledWith({ folderPath: '/input', outPath: '/output' })
    expect(setFolderInfo.mock.calls[0][0]).not.toHaveProperty('password')
    expect(encryptFileReq).toHaveBeenCalledTimes(1)
    expect(ElMessage.success).toHaveBeenCalledWith('done')
  })
})
