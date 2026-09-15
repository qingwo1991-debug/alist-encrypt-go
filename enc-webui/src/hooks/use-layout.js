/**
 * 判断是否是外链
 * @param {string} path
 * @returns {Boolean}
 */
import { onBeforeMount, onBeforeUnmount, onMounted, ref } from 'vue'
import { useBasicStore } from '@/store/basic'
export function isExternal(path) {
  return /^(https?:|mailto:|tel:)/.test(path)
}

/*移动端断点判断（可共享状态）：宽 < 992 视为手机/窄屏*/
const WIDTH = 992
export const isMobileState = ref(false)

export function setIsMobile(val) {
  isMobileState.value = val
}

/*判断窗口变化控制侧边栏收起或展开*/
export function resizeHandler() {
  const { body } = document
  const basicStore = useBasicStore()
  const isMobile = () => {
    const rect = body.getBoundingClientRect()
    return rect.width - 1 < WIDTH
  }
  const resizeHandler = () => {
    if (!document.hidden) {
      const mobile = isMobile()
      setIsMobile(mobile)
      if (mobile) {
        /*此处只做根据window尺寸关闭sideBar功能*/
        basicStore.setSidebarOpen(false)
      } else {
        basicStore.setSidebarOpen(true)
      }
    }
  }
  onBeforeMount(() => {
    window.addEventListener('resize', resizeHandler)
  })
  onMounted(() => {
    const mobile = isMobile()
    setIsMobile(mobile)
    if (mobile) {
      basicStore.setSidebarOpen(false)
    } else {
      basicStore.setSidebarOpen(true)
    }
  })
  onBeforeUnmount(() => {
    window.removeEventListener('resize', resizeHandler)
  })
}
