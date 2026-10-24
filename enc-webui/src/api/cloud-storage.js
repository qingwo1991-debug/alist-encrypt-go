import axiosReq from '@/utils/axios-req'

// Use the local admin JWT transport, never the upstream file-browser session.
const request = (url, method, data, { signal } = {}) => axiosReq({
  url,
  method,
  data,
  signal,
  timeout: 20000,
  reqLoading: false,
  isNotTipErrorMsg: true,
  skipForbiddenAuthReset: true
})

export const getWopanStoragesReq = (options) => request('/enc-api/wopan/storages', 'get', undefined, options)

export const getWopanAutomationReq = (options) => request('/enc-api/wopan/automation', 'get', undefined, options)

// Saving the schedule never executes a clear. Only these strict JSON fields are sent.
export const saveWopanAutomationReq = (configuration, options) => request('/enc-api/wopan/automation', 'post', {
  enabled: configuration.enabled,
  storage_ids: [...configuration.storage_ids],
  interval_hours: configuration.interval_hours,
  confirmation_phrase: configuration.confirmation_phrase
}, options)

// axiosReq maps GET data to query parameters in its request interceptor.
export const getWopanQuotaReq = (storageId, options) => request('/enc-api/wopan/quota', 'get', { storage_id: storageId }, options)

export const prepareWopanRecycleReq = (storageId, options) => request('/enc-api/wopan/recycle/prepare', 'post', { storage_id: storageId }, options)

// One explicit user action makes one request. Do not retry destructive requests.
export const clearWopanRecycleReq = (confirmation, options) => request(
  '/enc-api/wopan/recycle/clear',
  'post',
  {
    storage_id: confirmation.storage_id,
    confirmation_token: confirmation.confirmation_token,
    confirmation_phrase: confirmation.confirmation_phrase
  },
  options
)
