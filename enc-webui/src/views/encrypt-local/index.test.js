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
        'el-button': true,
        'el-select': true,
        'el-option': true
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

  it('defaults new files to V3 with unchanged 16 MiB geometry', async () => {
    encryptFileReq.mockResolvedValue({ msg: 'done' })
    const setup = mountEncryptLocal().vm.$.setupState
    setup.folderForm.password = 'password'
    await setup.encryptFile()
    expect(encryptFileReq.mock.calls[0][0]).toMatchObject({ v2: false, v3ChunkSize: 0 })
  })

  it('sends the playback chunk opt-in per new file, without persisting it', async () => {
    encryptFileReq.mockResolvedValue({ msg: 'done' })
    const setup = mountEncryptLocal().vm.$.setupState
    setup.folderForm.password = 'password'
    setup.folderForm.v3ChunkSize = 1048576
    await setup.encryptFile()
    expect(encryptFileReq.mock.calls[0][0]).toMatchObject({ v2: false, v3ChunkSize: 1048576 })
    expect(setFolderInfo.mock.calls[0][0]).not.toHaveProperty('v3ChunkSize')
  })

  it.each(['v2', 'dec'])('omits new-file geometry from %s requests', async (mode) => {
    encryptFileReq.mockResolvedValue({ msg: 'done' })
    const setup = mountEncryptLocal().vm.$.setupState
    setup.folderForm.password = 'password'
    setup.folderForm.v3ChunkSize = 1048576
    setup.folderForm.v2 = mode === 'v2'
    setup.folderForm.operation = mode === 'dec' ? 'dec' : 'enc'
    await setup.encryptFile()
    const request = encryptFileReq.mock.calls[0][0]
    expect(request).not.toHaveProperty('v3ChunkSize')
    if (mode === 'v2') expect(request.v2).toBe(true)
    else expect(request).not.toHaveProperty('v2')
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
