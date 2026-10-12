import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const root = new URL('../android/app/src/main/kotlin/com/openlist/mobile/', import.meta.url)
const bridge = readFileSync(new URL('NativeNetworkBridge.kt', root), 'utf8')
const service = readFileSync(new URL('OpenListService.kt', root), 'utf8')

// Source contract regressions, NOT Android socket/DNS instrumentation evidence.
test('FD ownership duplicates the descriptor and never adopts the Go FD', () => {
  assert.match(bridge, /ParcelFileDescriptor\.fromFd\(fd\.toInt\(\)\)\.use/)
  assert.match(bridge, /network\.bindSocket\(duplicate\.fileDescriptor\)/)
  assert.doesNotMatch(bridge, /adoptFd\(/)
})
test('selected DNS uses both address families on the captured Network with cancellation', () => {
  assert.match(bridge, /DnsResolver\.TYPE_A, DnsResolver\.TYPE_AAAA/)
  assert.match(bridge, /resolver\.query\(query\.network, host, type, 0, executor, query\.signals\[slot\]/)
  assert.match(bridge, /queries\[id\] !== query/)
  assert.match(bridge, /query\.signals\.forEach \{ it\.cancel\(\) \}/)
  assert.doesNotMatch(bridge, /getAllByName|Future\.get|networkHandle|SO_MARK/)
})
test('native DNS registry, callback queue and retained results are bounded', () => {
  assert.match(bridge, /MAX_QUERIES = 64/)
  assert.match(bridge, /queries\.size >= MAX_QUERIES/)
  assert.match(bridge, /ArrayBlockingQueue<Runnable>\(64\)/)
  assert.match(bridge, /timeoutMillis\.coerceAtMost\(15000\)/)
  assert.match(bridge, /query\.addresses\.size >= 64/)
  assert.match(bridge, /cancelQuery\(id, query\)/)
  assert.match(bridge, /callbacks\.shutdownNow\(\)/)
  assert.match(bridge, /deadlines\.shutdownNow\(\)/)
})
test('same-Service backend restart reinstalls monitoring with serialized idempotent lifecycle', () => {
  assert.match(service, /private fun startNetworkMonitoring\(\) = synchronized\(mNetworkLock\) \{\s*if \(mNativeNetworkBridge != null\) return@synchronized/)
  assert.match(service, /private fun stopNetworkMonitoring\(\) = synchronized\(mNetworkLock\)/)
  const startup = service.slice(service.indexOf('private fun startOpenListBackend()'))
  assert.match(startup, /startNetworkMonitoring\(\)[\s\S]*OpenList\.startup\(\)/)
})
test('old Android publishes no selected tokens and API24 default callback is guarded', () => {
  assert.match(bridge, /if \(Build\.VERSION\.SDK_INT >= Build\.VERSION_CODES\.Q\) \{/)
  assert.match(service, /if \(Build\.VERSION\.SDK_INT >= Build\.VERSION_CODES\.N\) \{[\s\S]*manager\.registerDefaultNetworkCallback\(defaultCallback\)/)
  assert.match(service, /NET_CAPABILITY_NOT_VPN/)
  assert.match(service, /!caps\.hasTransport\(NetworkCapabilities\.TRANSPORT_VPN\)/)
})
