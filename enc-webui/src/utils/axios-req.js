import axios from 'axios'
import { ElLoading, ElMessage } from 'element-plus'
import { useBasicStore } from '@/store/basic'

//使用axios.create()创建一个axios请求实例
const service = axios.create()
let authResetting = false

const cleanupRequest = (config) => {
  const requestState = config?.__encRequestState
  if (!requestState || requestState.cleaned) return

  requestState.cleaned = true
  if (requestState.cancelEntry) {
    const axiosPromiseArr = useBasicStore().axiosPromiseArr
    const index = axiosPromiseArr.indexOf(requestState.cancelEntry)
    if (index !== -1) axiosPromiseArr.splice(index, 1)
  }
  requestState.loadingInstance?.close()
}

const codeMatches = (code, candidates) => candidates.has(String(code))

const errorMessage = (err) => {
  return err?.response?.data?.msg || err?.response?.data?.message || err?.message || String(err || '请求失败')
}

const resetExpiredSession = () => {
  if (authResetting) return
  authResetting = true
  useBasicStore().resetStateAndToLogin()
  window.setTimeout(() => {
    authResetting = false
  }, 500)
}
//请求前拦截
service.interceptors.request.use(
  (req) => {
    const { token, axiosPromiseArr } = useBasicStore()
    const requestState = {
      cancelEntry: null,
      loadingInstance: null,
      cleaned: false
    }
    req.__encRequestState = requestState
    //axiosPromiseArr收集请求地址,用于取消请求
    req.cancelToken = new axios.CancelToken((cancel) => {
      const cancelEntry = {
        url: req.url,
        cancel: (message) => {
          cleanupRequest(req)
          cancel(message)
        }
      }
      requestState.cancelEntry = cancelEntry
      axiosPromiseArr.push(cancelEntry)
    })
    //设置token到header，nginx不支持下划线的headers
    req.headers['AUTHORIZETOKEN'] = token
    //如果req.method给get 请求参数设置为 ?name=xxx
    if ('get'.includes(req.method?.toLowerCase())) req.params = req.data

    //req loading
    // @ts-ignore
    if (req.reqLoading ?? true) {
      requestState.loadingInstance = ElLoading.service({
        lock: true,
        fullscreen: true,
        // spinner: 'CircleCheck',
        text: '数据载入中...',
        background: 'rgba(0, 0, 0, 0.3)'
      })
    }

    return req
  },
  (err) => {
    //发送请求失败
    return Promise.reject(err)
  }
)
//请求后拦截
service.interceptors.response.use(
  (res) => {
    cleanupRequest(res.config)
    //download file
    if (['application/zip', 'zip', 'blob', 'arraybuffer'].includes(res.headers['content-type'])) {
      return res
    }
    const { code, msg } = res.data
    const successCodes = new Set(['0', '200', '20000'])
    const noAuthCodes = new Set(['401', '403'])
    if (codeMatches(code, successCodes)) {
      return res.data
    } else {
      if (codeMatches(code, noAuthCodes)) {
        resetExpiredSession()
      }
      // @ts-ignore
      if (!res.config?.isNotTipErrorMsg) {
        ElMessage.error({
          message: msg,
          duration: 2 * 1000
        })
      }
      return Promise.reject(msg)
    }
  },
  //响应报错
  (err) => {
    cleanupRequest(err?.config)
    const unauthorized = [401, 403].includes(err?.response?.status)
    if (unauthorized) {
      resetExpiredSession()
    }
    if (!err?.config?.isNotTipErrorMsg) {
      ElMessage.error({
        message: unauthorized ? '登录已过期，请重新登录' : errorMessage(err),
        duration: 2 * 1000
      })
    }
    return Promise.reject(err)
  }
)
//导出service实例给页面调用 , config->页面的配置
export default function axiosReq(config) {
  return service({
    baseURL: import.meta.env.VITE_APP_BASE_URL,
    timeout: 8000,
    ...config
  })
}
