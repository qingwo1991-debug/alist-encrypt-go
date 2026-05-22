<template>
  <div class="setting-alist-page scroll-y">
    <div class="setting-alist-shell">
      <div class="page-header">
        <div>
          <h3>Alist 服务配置</h3>
          <p>把常用配置收拢到可展开的分组里，预热日志默认隐藏，避免一打开就是长页。</p>
        </div>
        <div class="page-actions">
          <el-button type="primary" @click="saveAlistConfig">保存服务配置</el-button>
          <el-button type="warning" @click="saveProxyRouting">保存代理分流</el-button>
          <el-button type="info" plain @click="refreshProbeStats">刷新实时数据</el-button>
        </div>
      </div>

      <el-form ref="refSearchForm" :label-position="labelPosition" label-width="92px" :model="alistConfigForm" class="setting-form">
        <el-collapse v-model="expandedSections" class="setting-collapse">
          <el-collapse-item name="connection">
            <template #title>
              <div class="section-banner">基础连接</div>
            </template>
            <div class="section-body">
              <el-form-item label="服务器">
                <el-input v-model="alistConfigForm.serverHost" style="max-width: 280px" placeholder="192.168.1.100" />
                <span class="helper-text">alist 的 IP 或域名地址</span>
              </el-form-item>
              <el-form-item label="端口">
                <el-input v-model="alistConfigForm.serverPort" style="max-width: 280px" placeholder="5244" />
              </el-form-item>
              <el-form-item label="HTTPS">
                <el-switch v-model="alistConfigForm.https" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                <span class="helper-text">默认 HTTP</span>
              </el-form-item>
              <el-form-item label="后端 H2C">
                <el-switch v-model="alistConfigForm.enableH2c" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                <span class="helper-text">代理连接后端 Alist 时启用 h2c</span>
              </el-form-item>
              <el-form-item label="代理 H2C">
                <el-switch v-model="alistConfigForm.proxyH2c" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                <span class="helper-text">客户端连接代理时启用 h2c</span>
              </el-form-item>
            </div>
          </el-collapse-item>

          <el-collapse-item name="playback">
            <template #title>
              <div class="section-banner">播放与解密</div>
            </template>
            <div class="section-body">
              <el-form-item label="长期映射">
                <el-switch v-model="alistConfigForm.enableSizeMap" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                <span class="helper-text">缓存文件大小映射，减少探测请求</span>
              </el-form-item>
              <el-form-item label="映射 TTL">
                <el-input v-model="alistConfigForm.sizeMapTtlMinutes" style="max-width: 280px" placeholder="1440" />
                <span class="helper-text">分钟</span>
              </el-form-item>
              <el-form-item label="Range 兼容">
                <el-switch v-model="alistConfigForm.enableRangeCompatCache" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                <span class="helper-text">记录不支持 Range 的上游并降级</span>
              </el-form-item>
              <el-form-item label="降级阈值">
                <el-input v-model="alistConfigForm.rangeFailToDowngrade" style="max-width: 280px" placeholder="2" />
                <span class="helper-text">连续失败次数（1-10）</span>
              </el-form-item>
              <el-form-item label="恢复阈值">
                <el-input v-model="alistConfigForm.rangeSuccessToRecover" style="max-width: 280px" placeholder="3" />
                <span class="helper-text">连续成功次数（1-20）</span>
              </el-form-item>
              <el-form-item label="重探间隔">
                <el-input v-model="alistConfigForm.rangeReprobeMinutes" style="max-width: 280px" placeholder="30" />
                <span class="helper-text">分钟（1-1440）</span>
              </el-form-item>
              <el-form-item label="探测超时">
                <el-input v-model="alistConfigForm.rangeProbeTimeoutSeconds" style="max-width: 280px" placeholder="8" />
                <span class="helper-text">秒（2-60）</span>
              </el-form-item>
              <el-form-item label="元数据刷新">
                <el-input v-model="alistConfigForm.upstreamStalenessMinutes" style="max-width: 280px" placeholder="30" />
                <span class="helper-text">分钟（0=默认 30），超过后自动重新获取 raw_url</span>
              </el-form-item>
              <el-form-item label="并行解密">
                <el-switch v-model="alistConfigForm.enableParallelDecrypt" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                <span class="helper-text">大文件分片并行解密</span>
              </el-form-item>
              <el-form-item label="并发数">
                <el-input v-model="alistConfigForm.parallelDecryptConcurrency" style="max-width: 280px" placeholder="4" />
              </el-form-item>
              <el-form-item label="缓冲区 KB">
                <el-input v-model="alistConfigForm.streamBufferKb" style="max-width: 280px" placeholder="512" />
              </el-form-item>
            </div>
          </el-collapse-item>

          <el-collapse-item name="scan">
            <template #title>
              <div class="section-banner section-banner--accent">扫描预取配置</div>
            </template>
            <div class="section-body">
              <el-form-item label="扫描账号">
                <el-input v-model="alistConfigForm.scanUsername" style="max-width: 280px" placeholder="scanner" />
                <span class="helper-text">用于启动扫描、后台探测和 WebDAV 预热</span>
              </el-form-item>
              <el-form-item label="扫描密码">
                <el-input v-model="alistConfigForm.scanPassword" style="max-width: 280px" type="password" show-password placeholder="password" />
              </el-form-item>
              <el-form-item label="授权头">
                <el-input v-model="alistConfigForm.scanAuthHeader" style="max-width: 540px" placeholder="Bearer xxx 或 Basic xxxxxx" />
                <span class="helper-text">填写后优先于扫描账号密码</span>
              </el-form-item>
              <el-form-item label="配置校验">
                <el-button type="primary" plain @click="validateScanConfig">校验扫描账号</el-button>
                <span v-if="scanValidationResult" :style="{ marginLeft: '12px', color: scanValidationResult.ok ? '#67c23a' : '#f56c6c' }">
                  {{ scanValidationResult.message }}
                  <template v-if="scanValidationResult.status_code"> (HTTP {{ scanValidationResult.status_code }})</template>
                </span>
              </el-form-item>
              <el-form-item v-if="scanValidationResult" label="校验详情">
                <div class="info-block">
                  <div>目标地址: {{ scanValidationResult.target_url || '-' }}</div>
                  <div>认证方式: {{ scanValidationResult.auth_mode || '-' }}</div>
                  <div>响应摘要: {{ scanValidationResult.response_hint || '-' }}</div>
                </div>
              </el-form-item>
            </div>
          </el-collapse-item>

          <el-collapse-item name="observability">
            <template #title>
              <div class="section-banner">预热观测</div>
            </template>
            <div class="section-body">
              <div class="metric-grid">
                <div class="metric-card">
                  <div class="metric-card__title">后台预取</div>
                  <div class="metric-card__content">
                    <div>最近刷新: {{ probeStats.updatedAt || '-' }}</div>
                    <div>首帧预热累计: {{ probeStats.warmupEnqueueCount }}</div>
                  </div>
                </div>
                <div class="metric-card">
                  <div class="metric-card__title">预取队列</div>
                  <div class="metric-card__content">
                    <div>队列长度: {{ probeStats.queueLen }} / {{ probeStats.queueCap }}</div>
                    <div>累计入队: {{ probeStats.enqueuedTotal }}，累计丢弃: {{ probeStats.droppedTotal }}</div>
                    <div>冷却跳过: {{ probeStats.cooldownSkips }}，工作协程: {{ probeStats.workers }}，运行中: {{ probeStats.runningCount }}</div>
                    <div>单网盘并发: {{ probeStats.providerLimit }}</div>
                  </div>
                </div>
                <div class="metric-card">
                  <div class="metric-card__title">元数据预热</div>
                  <div class="metric-card__content">
                    <div>累计触发: {{ prefetchStats.total }}，成功: {{ prefetchStats.success }}，跳过: {{ prefetchStats.skipped }}</div>
                    <div>过期触发: {{ prefetchStats.staleTriggers }}</div>
                    <div>上次更新: {{ prefetchStats.lastAt || '-' }}</div>
                  </div>
                </div>
                <div class="metric-card">
                  <div class="metric-card__title">文件级预热</div>
                  <div class="metric-card__content">
                    <div>发现: {{ probeStats.filesDiscoveredTotal }}，入队: {{ probeStats.filesQueuedTotal }}，成功: {{ probeStats.filesSucceededTotal }}</div>
                    <div>失败: {{ probeStats.filesFailedTotal }}，跳过: {{ probeStats.filesSkippedTotal }}</div>
                    <div>raw_url: {{ probeStats.filesRawURLFetched }}，Range: {{ probeStats.filesRangeProbed }}，落库: {{ probeStats.filesMetaPersisted }}</div>
                    <div>命中: {{ probeStats.consumerHitTotal }}，命中率: {{ probeConsumerHitRate }}</div>
                  </div>
                </div>
              </div>

              <div class="summary-grid">
                <div class="summary-card">
                  <div class="summary-card__title">来源统计</div>
                  <div>{{ sourceSummary.length ? sourceSummary.join('，') : '-' }}</div>
                </div>
                <div class="summary-card">
                  <div class="summary-card__title">状态统计</div>
                  <div>{{ statusSummary.length ? statusSummary.join('，') : '-' }}</div>
                </div>
                <div class="summary-card">
                  <div class="summary-card__title">失败原因</div>
                  <div>{{ failureSummary.length ? failureSummary.join('，') : '-' }}</div>
                </div>
                <div class="summary-card">
                  <div class="summary-card__title">预热状态</div>
                  <div>{{ warmStateSummary.length ? warmStateSummary.join('，') : '-' }}</div>
                  <div>失效事件累计: {{ probeStats.invalidationsTotal || 0 }}</div>
                </div>
              </div>

              <div class="log-panel">
                <div class="log-panel__header">
                  <div>
                    <strong>最近预热文件</strong>
                    <span class="helper-text">共 {{ probeStats.recentRecords.length }} 条，默认隐藏避免长列表撑爆页面</span>
                  </div>
                  <el-button link type="primary" @click="toggleLogPanel('records')">{{ logPanels.records ? '收起' : '展开' }}</el-button>
                </div>
                <div v-if="logPanels.records" class="log-panel__body">
                  <div v-if="paginatedRecentRecords.length === 0" class="empty-log">暂无预热记录</div>
                  <div v-for="record in paginatedRecentRecords" :key="`${record.display_path}-${record.finished_at}-${record.status}`" class="record-item">
                    <div><strong>{{ record.file_name || record.display_path }}</strong> <span class="record-tag">[{{ record.source }} / {{ record.status }} / {{ record.warm_state || '-' }}]</span></div>
                    <div>路径: {{ record.display_path }}</div>
                    <div>大小: {{ record.reported_size || 0 }} -> {{ record.resolved_size || 0 }}，来源: {{ record.size_source || '-' }}，认证: {{ record.used_auth_mode || '-' }}</div>
                    <div>raw_url: {{ record.raw_url_fetched ? 'yes' : 'no' }}，range: {{ record.range_probed ? 'yes' : 'no' }}，meta: {{ record.meta_persisted ? 'yes' : 'no' }}，排队: {{ record.queue_wait_ms || 0 }}ms</div>
                    <div>命中数: {{ record.consumer_hit_count || 0 }}，上次命中: {{ record.last_consumer_hit_at || '-' }}，失效: {{ record.invalidated ? 'yes' : 'no' }}</div>
                    <div>开始: {{ record.started_at || '-' }}，结束: {{ record.finished_at || '-' }}，耗时: {{ record.duration_ms || 0 }}ms<span v-if="record.failure_reason">，失败: {{ record.failure_reason }}</span></div>
                  </div>
                  <el-pagination
                    v-if="probeStats.recentRecords.length > logPageSizes.records"
                    background
                    layout="prev, pager, next"
                    :page-size="logPageSizes.records"
                    :total="probeStats.recentRecords.length"
                    :current-page="logPages.records"
                    @current-change="(page) => handleLogPageChange('records', page)"
                  />
                </div>
              </div>

              <div class="log-panel">
                <div class="log-panel__header">
                  <div>
                    <strong>最近命中文件</strong>
                    <span class="helper-text">共 {{ probeStats.recentConsumerHits.length }} 条</span>
                  </div>
                  <el-button link type="primary" @click="toggleLogPanel('hits')">{{ logPanels.hits ? '收起' : '展开' }}</el-button>
                </div>
                <div v-if="logPanels.hits" class="log-panel__body">
                  <div v-if="paginatedRecentConsumerHits.length === 0" class="empty-log">暂无命中记录</div>
                  <div v-for="hit in paginatedRecentConsumerHits" :key="`${hit.display_path}-${hit.hit_at}-${hit.scenario}`" class="record-item">
                    <div><strong>{{ hit.file_name || hit.display_path }}</strong> <span class="record-tag">[{{ hit.source }} -> {{ hit.scenario }}]</span></div>
                    <div>路径: {{ hit.display_path }}</div>
                    <div>命中时间: {{ hit.hit_at || '-' }}</div>
                  </div>
                  <el-pagination
                    v-if="probeStats.recentConsumerHits.length > logPageSizes.hits"
                    background
                    layout="prev, pager, next"
                    :page-size="logPageSizes.hits"
                    :total="probeStats.recentConsumerHits.length"
                    :current-page="logPages.hits"
                    @current-change="(page) => handleLogPageChange('hits', page)"
                  />
                </div>
              </div>

              <div class="log-panel">
                <div class="log-panel__header">
                  <div>
                    <strong>当前预热文件</strong>
                    <span class="helper-text">共 {{ probeStats.currentWarmStates.length }} 条</span>
                  </div>
                  <el-button link type="primary" @click="toggleLogPanel('warm')">{{ logPanels.warm ? '收起' : '展开' }}</el-button>
                </div>
                <div v-if="logPanels.warm" class="log-panel__body">
                  <div v-if="paginatedCurrentWarmStates.length === 0" class="empty-log">暂无活跃预热状态</div>
                  <div v-for="item in paginatedCurrentWarmStates" :key="`${item.display_path}-${item.finished_at}`" class="record-item">
                    <div><strong>{{ item.file_name || item.display_path }}</strong> <span class="record-tag">[{{ item.source || '-' }} / {{ item.state || '-' }}]</span></div>
                    <div>路径: {{ item.display_path }}</div>
                    <div>完成时间: {{ item.finished_at || '-' }}</div>
                    <div>命中数: {{ item.consumer_hit_count || 0 }}，上次命中: {{ item.last_consumer_hit_at || '-' }}</div>
                  </div>
                  <el-pagination
                    v-if="probeStats.currentWarmStates.length > logPageSizes.warm"
                    background
                    layout="prev, pager, next"
                    :page-size="logPageSizes.warm"
                    :total="probeStats.currentWarmStates.length"
                    :current-page="logPages.warm"
                    @current-change="(page) => handleLogPageChange('warm', page)"
                  />
                </div>
              </div>

              <div class="log-panel">
                <div class="log-panel__header">
                  <div>
                    <strong>最近失效事件</strong>
                    <span class="helper-text">共 {{ probeStats.recentInvalidations.length }} 条</span>
                  </div>
                  <el-button link type="primary" @click="toggleLogPanel('invalidations')">{{ logPanels.invalidations ? '收起' : '展开' }}</el-button>
                </div>
                <div v-if="logPanels.invalidations" class="log-panel__body">
                  <div v-if="paginatedRecentInvalidations.length === 0" class="empty-log">暂无失效记录</div>
                  <div v-for="item in paginatedRecentInvalidations" :key="`${item.display_path}-${item.at}-${item.reason}`" class="record-item">
                    <div><strong>{{ item.display_path }}</strong></div>
                    <div>原因: {{ item.reason || '-' }}</div>
                    <div>时间: {{ item.at || '-' }}</div>
                  </div>
                  <el-pagination
                    v-if="probeStats.recentInvalidations.length > logPageSizes.invalidations"
                    background
                    layout="prev, pager, next"
                    :page-size="logPageSizes.invalidations"
                    :total="probeStats.recentInvalidations.length"
                    :current-page="logPages.invalidations"
                    @current-change="(page) => handleLogPageChange('invalidations', page)"
                  />
                </div>
              </div>
            </div>
          </el-collapse-item>

          <el-collapse-item name="proxy">
            <template #title>
              <div class="section-banner">代理分流配置</div>
            </template>
            <div class="section-body">
              <el-form-item label="代理模式">
                <el-radio-group v-model="proxyRoutingForm.mode" size="small">
                  <el-radio label="direct" border>直连</el-radio>
                  <el-radio label="env" border>环境变量</el-radio>
                  <el-radio label="fixed" border>固定代理</el-radio>
                  <el-radio label="rules" border>规则分流</el-radio>
                </el-radio-group>
              </el-form-item>
              <el-form-item label="代理地址">
                <el-input v-model="proxyRoutingForm.url" style="max-width: 420px" placeholder="http://host.docker.internal:7890" />
              </el-form-item>
              <el-form-item label="网盘多选">
                <el-select
                  v-model="proxyRoutingForm.selectedProviderIDs"
                  style="width: 720px"
                  multiple
                  collapse-tags
                  collapse-tags-tooltip
                  filterable
                  clearable
                  placeholder="选择要走代理的网盘（支持多选）"
                >
                  <el-option
                    v-for="provider in providerOptions"
                    :key="provider.id"
                    :label="`${provider.provider_name_zh} (${provider.provider_name_en}) [${provider.category}]`"
                    :value="provider.id"
                  />
                </el-select>
              </el-form-item>
              <el-form-item label="域名预览">
                <el-input v-model="selectedDomainPreview" type="textarea" :rows="4" readonly style="max-width: 720px" />
              </el-form-item>
              <el-form-item label="字典操作">
                <el-button type="primary" plain @click="refreshProviderDictionary">从 OpenList 刷新字典</el-button>
                <span class="helper-text">显示中文网盘名，名单外默认直连</span>
              </el-form-item>
            </div>
          </el-collapse-item>

          <el-collapse-item name="password">
            <template #title>
              <div class="section-banner">密码规则</div>
            </template>
            <div class="section-body">
              <el-form-item label="密码设置">
                <el-button type="success" @click="addPasswd">添加规则</el-button>
              </el-form-item>
              <div class="passwd-list">
                <div v-for="(item, index) in alistConfigForm.passwdList" :key="item.id" class="passwd-card">
                  <div class="passwd-card__header">
                    <strong>配置 {{ index + 1 }}</strong>
                    <el-button type="danger" :icon="Delete" circle @click="delPasswd(index)" />
                  </div>
                  <el-form-item label="算法">
                    <el-radio-group v-model="item.encType" size="small">
                      <el-radio label="aesctr" border>AES-CTR</el-radio>
                      <el-radio label="rc4" border>RC4</el-radio>
                      <el-radio label="chacha20" border>ChaCha20</el-radio>
                    </el-radio-group>
                    <span class="helper-inline">开启</span>
                    <el-switch v-model="item.enable" class="ml-2" style="--el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                  </el-form-item>
                  <el-form-item label="密码">
                    <el-input v-model="item.password" style="max-width: 280px" placeholder="12341234" />
                  </el-form-item>
                  <el-form-item label="文件名">
                    <span class="helper-inline">加密</span>
                    <el-switch v-model="item.encName" class="ml-2" style="margin-right: 10px; --el-switch-on-color: #13ce66; --el-switch-off-color: #ff4949" />
                    <span class="helper-inline">后缀</span>
                    <el-input v-model="item.encSuffix" style="max-width: 180px; margin-left: 10px" placeholder=".bin / 默认原文件名后缀" />
                  </el-form-item>
                  <el-form-item label="备注">
                    <el-input v-model="item.describe" style="max-width: 280px" placeholder="备注描述" />
                  </el-form-item>
                  <el-form-item label="路径">
                    <el-input v-model="item.encPath" style="max-width: 420px" placeholder="多个目录用逗号隔开" />
                    <span class="helper-text">example: encrypt/*</span>
                  </el-form-item>
                  <el-form-item label="子密码">
                    <span class="helper-inline">根据文件夹名字自动识别文件夹秘钥</span>
                    <el-button type="success" size="small" style="margin-left: 10px" @click="checkFoldName(item)">获取</el-button>
                  </el-form-item>
                </div>
              </div>
            </div>
          </el-collapse-item>

          <el-collapse-item name="maintenance">
            <template #title>
              <div class="section-banner">维护工具</div>
            </template>
            <div class="section-body">
              <el-form-item label="旧数据清理">
                <el-button type="danger" plain @click="cleanupLegacyBoltDB">清理旧 BoltDB 数据</el-button>
                <span v-if="cleanupMsg" :style="{ marginLeft: '12px', color: cleanupOk ? '#67c23a' : '#f56c6c' }">{{ cleanupMsg }}</span>
                <span class="helper-text">仅在配置 MySQL 后可用，清理后无法找回</span>
              </el-form-item>
            </div>
          </el-collapse-item>
        </el-collapse>

        <div class="footer-actions">
          <el-button type="primary" @click="saveAlistConfig">保存服务配置</el-button>
          <el-button type="warning" @click="saveProxyRouting">保存代理分流</el-button>
        </div>

        <el-dialog v-model="dialogFolderFormVisible" title="获取文件夹密文" style="min-width: 320px">
          <el-tabs v-model="activeName" class="demo-tabs">
            <el-tab-pane label="加密名字" name="encode">
              <el-form :model="folderForm">
                <el-form-item label="文件夹名称">
                  <el-input v-model="folderForm.folderName" style="max-width: 260px" placeholder="folder name" />
                </el-form-item>
                <el-form-item label="算法类型">
                  <el-radio-group v-model="folderForm.folderEncType" style="margin: 0 15px" size="small">
                    <el-radio label="aesctr" border>AES-CTR</el-radio>
                    <el-radio label="rc4" border>RC4</el-radio>
                    <el-radio label="chacha20" border>ChaCha20</el-radio>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="文件夹密码">
                  <el-input v-model="folderForm.folderPasswd" style="max-width: 260px" placeholder="123456" />
                </el-form-item>
                <el-form-item label="加密结果">
                  {{ folderForm.folderNameEnc }}
                </el-form-item>
                <el-button type="success" @click="encodeFoldName">查询</el-button>
              </el-form>
            </el-tab-pane>
            <el-tab-pane label="解密名字" name="decode">
              <el-form :model="folderForm">
                <el-form-item label="文件夹名称">
                  <el-input v-model="folderForm.folderNameEnc" style="max-width: 260px" placeholder="folder name" />
                </el-form-item>
                <el-form-item label="算法类型">
                  {{ folderForm.folderEncType }}
                </el-form-item>
                <el-form-item label="文件夹密码">
                  {{ folderForm.folderPasswd }}
                </el-form-item>
                <el-button type="success" @click="decodeFoldName">解密</el-button>
              </el-form>
            </el-tab-pane>
          </el-tabs>
        </el-dialog>
      </el-form>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, reactive, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useConfigStore } from '@/store/config'
import {
  getAlistConfigReq,
  saveAlistConfigReq,
  validateScanConfigReq,
  encodeFoldNameReq,
  decodeFoldNameReq,
  getSchemeConfigReq,
  saveSchemeConfigReq,
  getProxyDomainDictionaryReq,
  refreshProxyDomainDictionaryReq,
  getProxyRoutingConfigReq,
  saveProxyRoutingConfigReq,
  getStatsReq,
  cleanupLegacyBoltDBReq
} from '@/api/user'
import { Delete } from '@element-plus/icons-vue'

const labelPosition = ref('right')
const dialogFolderFormVisible = ref(false)
const activeName = ref('encode')
const expandedSections = ref(['connection', 'scan', 'password'])
const statsRefreshTimer = ref(null)
const providerOptions = ref([])
const scanValidationResult = ref(null)
const cleanupMsg = ref('')
const cleanupOk = ref(false)
const refSearchForm = ref()

const { setLanguage } = useConfigStore()
const changeLanguage = (langParam) => {
  setLanguage(langParam)
}
void changeLanguage

const logPageSizes = {
  records: 12,
  hits: 8,
  warm: 8,
  invalidations: 8
}

const logPanels = reactive({
  records: false,
  hits: false,
  warm: false,
  invalidations: false
})

const logPages = reactive({
  records: 1,
  hits: 1,
  warm: 1,
  invalidations: 1
})

const folderForm = reactive({
  folderName: 'my video',
  encType: 'aesctr',
  folderPasswd: '123456',
  folderNameEnc: '',
  folderEncType: 'rc4',
  password: ''
})

const alistConfigForm = reactive({
  name: '',
  path: '/*',
  describe: '',
  serverHost: '192.168.1.100',
  serverPort: '5244',
  https: false,
  enableH2c: false,
  proxyH2c: false,
  enableSizeMap: true,
  sizeMapTtlMinutes: 1440,
  enableRangeCompatCache: true,
  rangeFailToDowngrade: 2,
  rangeSuccessToRecover: 3,
  rangeReprobeMinutes: 30,
  rangeProbeTimeoutSeconds: 8,
  upstreamStalenessMinutes: 30,
  enableParallelDecrypt: false,
  parallelDecryptConcurrency: 4,
  streamBufferKb: 512,
  scanUsername: '',
  scanPassword: '',
  scanAuthHeader: '',
  passwdList: [
    {
      id: Math.random(),
      password: '123456',
      encType: 'aesctr',
      enable: false,
      encName: false,
      encSuffix: '',
      describe: 'my video',
      encPath: '333'
    }
  ]
})

const probeStats = reactive({
  queueLen: 0,
  queueCap: 0,
  enqueuedTotal: 0,
  droppedTotal: 0,
  cooldownSkips: 0,
  workers: 0,
  runningCount: 0,
  providerLimit: 0,
  warmupEnqueueCount: 0,
  updatedAt: '',
  filesDiscoveredTotal: 0,
  filesQueuedTotal: 0,
  filesSucceededTotal: 0,
  filesFailedTotal: 0,
  filesSkippedTotal: 0,
  filesRawURLFetched: 0,
  filesRangeProbed: 0,
  filesMetaPersisted: 0,
  consumerHitTotal: 0,
  consumerHitRate: 0,
  lastSuccessAt: '',
  lastFailureAt: '',
  lastRecordFinishedAt: '',
  sourceCounts: {},
  statusCounts: {},
  failureReasons: {},
  recentRecords: [],
  consumerHitsBySource: {},
  consumerHitsByScenario: {},
  recentConsumerHits: [],
  invalidationsTotal: 0,
  warmStateCounts: {},
  currentWarmStates: [],
  recentInvalidations: []
})

const prefetchStats = reactive({
  total: 0,
  success: 0,
  skipped: 0,
  staleTriggers: 0,
  lastAt: ''
})

const proxyRoutingForm = reactive({
  mode: 'direct',
  url: '',
  noProxy: [],
  selectedProviderIDs: [],
  selectedDomains: [],
  rules: [],
  dial_timeout_seconds: 30,
  tls_handshake_timeout_seconds: 10,
  response_header_timeout_seconds: 15
})

const collectSelectedDomains = () => {
  const selectedSet = new Set((proxyRoutingForm.selectedProviderIDs || []).map((item) => String(item).toLowerCase()))
  const domains = []
  for (const provider of providerOptions.value) {
    if (!selectedSet.has(String(provider.id).toLowerCase())) {
      continue
    }
    for (const domain of provider.domains || []) {
      domains.push(domain)
    }
  }
  return [...new Set(domains)].sort()
}

const selectedDomainPreview = computed(() => collectSelectedDomains().join(', '))

const summaryEntries = (sourceMap) => {
  return Object.entries(sourceMap || {})
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .map(([key, value]) => `${key}: ${value}`)
}

const sourceSummary = computed(() => summaryEntries(probeStats.sourceCounts))
const statusSummary = computed(() => summaryEntries(probeStats.statusCounts))
const failureSummary = computed(() => summaryEntries(probeStats.failureReasons).slice(0, 8))
const consumerSourceSummary = computed(() => summaryEntries(probeStats.consumerHitsBySource))
const consumerScenarioSummary = computed(() => summaryEntries(probeStats.consumerHitsByScenario))
const warmStateSummary = computed(() => summaryEntries(probeStats.warmStateCounts))
const probeConsumerHitRate = computed(() => `${((probeStats.consumerHitRate || 0) * 100).toFixed(1)}%`)

const paginate = (list, page, pageSize) => {
  const start = (page - 1) * pageSize
  return (list || []).slice(start, start + pageSize)
}

const paginatedRecentRecords = computed(() => paginate(probeStats.recentRecords, logPages.records, logPageSizes.records))
const paginatedRecentConsumerHits = computed(() => paginate(probeStats.recentConsumerHits, logPages.hits, logPageSizes.hits))
const paginatedCurrentWarmStates = computed(() => paginate(probeStats.currentWarmStates, logPages.warm, logPageSizes.warm))
const paginatedRecentInvalidations = computed(() => paginate(probeStats.recentInvalidations, logPages.invalidations, logPageSizes.invalidations))

const toggleLogPanel = (name) => {
  logPanels[name] = !logPanels[name]
}

const handleLogPageChange = (name, page) => {
  logPages[name] = page
}

const addPasswd = () => {
  alistConfigForm.passwdList.push({
    id: Math.random(),
    password: '123456',
    encType: 'aesctr',
    enable: true,
    encName: false,
    encSuffix: '',
    describe: 'my video',
    encPath: '/aliyun/encrypt/*'
  })
}

const delPasswd = (index) => {
  alistConfigForm.passwdList.splice(index, 1)
}

const checkFoldName = (item) => {
  dialogFolderFormVisible.value = true
  folderForm.password = item.password
  folderForm.encType = item.encType
}

const encodeFoldName = async () => {
  const res = await encodeFoldNameReq(folderForm)
  folderForm.folderNameEnc = `${folderForm.folderName}_${res.data.folderNameEnc}`
}

const decodeFoldName = async () => {
  const res = await decodeFoldNameReq(folderForm)
  folderForm.folderPasswd = res.data.folderPasswd
  folderForm.folderEncType = res.data.folderEncType
}

const saveAlistConfig = async () => {
  const toInt = (v, d) => {
    const n = Number.parseInt(v, 10)
    return Number.isFinite(n) ? n : d
  }
  const clamp = (v, min, max) => Math.min(max, Math.max(min, v))
  alistConfigForm.rangeFailToDowngrade = clamp(toInt(alistConfigForm.rangeFailToDowngrade, 2), 1, 10)
  alistConfigForm.rangeSuccessToRecover = clamp(toInt(alistConfigForm.rangeSuccessToRecover, 3), 1, 20)
  alistConfigForm.rangeReprobeMinutes = clamp(toInt(alistConfigForm.rangeReprobeMinutes, 30), 1, 1440)
  alistConfigForm.rangeProbeTimeoutSeconds = clamp(toInt(alistConfigForm.rangeProbeTimeoutSeconds, 8), 2, 60)

  for (const passwdInfo of alistConfigForm.passwdList) {
    if (typeof passwdInfo.encPath === 'string') {
      passwdInfo.encPath = passwdInfo.encPath
        .split(',')
        .map(item => item.trim())
        .filter(item => item.length > 0)
        .join(',')
    }
  }

  saveAlistConfigReq(alistConfigForm).then((res) => {
    ElMessage.success(res.msg)
  })
  try {
    const schemeRes = await getSchemeConfigReq()
    const schemeData = schemeRes.data || {}
    schemeData.enable_h2c = alistConfigForm.proxyH2c
    await saveSchemeConfigReq(schemeData)
  } catch (err) {
    console.error('Failed to save proxy H2C setting:', err)
  }
}

const loadProxyDictionary = async () => {
  const res = await getProxyDomainDictionaryReq()
  const providers = (res?.data?.providers || []).map((item) => ({
    ...item,
    id: String(item.id || '').toLowerCase()
  }))
  providerOptions.value = providers
  if ((proxyRoutingForm.selectedProviderIDs || []).length === 0) {
    proxyRoutingForm.selectedProviderIDs = providers.filter((item) => item.default_selected).map((item) => item.id)
  }
}

const refreshProviderDictionary = async () => {
  const res = await refreshProxyDomainDictionaryReq()
  const providers = (res?.data?.providers || []).map((item) => ({
    ...item,
    id: String(item.id || '').toLowerCase()
  }))
  providerOptions.value = providers
  ElMessage.success('已刷新网盘字典')
}

const loadProxyRouting = async () => {
  const res = await getProxyRoutingConfigReq()
  if (res?.data) {
    Object.assign(proxyRoutingForm, {
      ...proxyRoutingForm,
      ...res.data,
      selectedProviderIDs: (res.data.selected_provider_ids || res.data.selectedProviderIDs || []).map((item) => String(item).toLowerCase()),
      selectedDomains: res.data.selected_domains || res.data.selectedDomains || []
    })
  }
}

const saveProxyRouting = async () => {
  if (proxyRoutingForm.mode === 'rules' && !proxyRoutingForm.url) {
    ElMessage.error('规则分流模式需要填写代理地址')
    return
  }
  const payload = {
    ...proxyRoutingForm,
    selectedDomains: collectSelectedDomains(),
    selected_provider_ids: proxyRoutingForm.selectedProviderIDs,
    selected_domains: collectSelectedDomains()
  }
  const res = await saveProxyRoutingConfigReq(payload)
  ElMessage.success(res.msg || '保存成功')
}

const cleanupLegacyBoltDB = async () => {
  cleanupMsg.value = ''
  cleanupOk.value = false
  try {
    const res = await cleanupLegacyBoltDBReq()
    cleanupMsg.value = res.msg || res.data?.msg || '操作完成'
    cleanupOk.value = !!(res.code === 0 || res.code === 200)
  } catch (err) {
    cleanupMsg.value = err?.msg || err?.message || '请求失败'
    cleanupOk.value = false
  }
}

const validateScanConfig = async () => {
  const res = await validateScanConfigReq(alistConfigForm)
  scanValidationResult.value = res.data
  if (res.data?.ok) {
    ElMessage.success(res.data.message || '扫描账号可用')
  } else {
    ElMessage.warning(res.data?.message || '扫描账号不可用')
  }
}

const refreshProbeStats = async () => {
  const res = await getStatsReq({ reqLoading: false })
  const scheduler = res?.data?.probe_scheduler || {}
  const stream = res?.data?.stream || {}
  const proxyPrefetch = res?.data?.proxy?.prefetch || {}
  probeStats.queueLen = scheduler.queue_len || 0
  probeStats.queueCap = scheduler.queue_cap || 0
  probeStats.enqueuedTotal = scheduler.enqueued_total || 0
  probeStats.droppedTotal = scheduler.dropped_total || 0
  probeStats.cooldownSkips = scheduler.cooldown_skips || 0
  probeStats.workers = scheduler.workers || 0
  probeStats.runningCount = scheduler.running_count || 0
  probeStats.providerLimit = scheduler.provider_limit || 0
  probeStats.warmupEnqueueCount = stream.warmup_enqueue_count || 0
  probeStats.filesDiscoveredTotal = scheduler.files_discovered_total || 0
  probeStats.filesQueuedTotal = scheduler.files_queued_total || 0
  probeStats.filesSucceededTotal = scheduler.files_succeeded_total || 0
  probeStats.filesFailedTotal = scheduler.files_failed_total || 0
  probeStats.filesSkippedTotal = scheduler.files_skipped_total || 0
  probeStats.filesRawURLFetched = scheduler.files_raw_url_fetched || 0
  probeStats.filesRangeProbed = scheduler.files_range_probed || 0
  probeStats.filesMetaPersisted = scheduler.files_meta_persisted || 0
  probeStats.consumerHitTotal = scheduler.consumer_hit_total || 0
  probeStats.consumerHitRate = scheduler.consumer_hit_rate || 0
  probeStats.lastSuccessAt = scheduler.last_success_at || ''
  probeStats.lastFailureAt = scheduler.last_failure_at || ''
  probeStats.lastRecordFinishedAt = scheduler.last_record_finished_at || ''
  probeStats.sourceCounts = scheduler.source_counts || {}
  probeStats.statusCounts = scheduler.status_counts || {}
  probeStats.failureReasons = scheduler.failure_reasons || {}
  probeStats.recentRecords = scheduler.recent_records || []
  probeStats.consumerHitsBySource = scheduler.consumer_hits_by_source || {}
  probeStats.consumerHitsByScenario = scheduler.consumer_hits_by_scenario || {}
  probeStats.recentConsumerHits = scheduler.recent_consumer_hits || []
  probeStats.invalidationsTotal = scheduler.invalidations_total || 0
  probeStats.warmStateCounts = scheduler.warm_state_counts || {}
  probeStats.currentWarmStates = scheduler.current_warm_states || []
  probeStats.recentInvalidations = scheduler.recent_invalidations || []
  probeStats.updatedAt = new Date().toLocaleTimeString()

  prefetchStats.total = proxyPrefetch.total || 0
  prefetchStats.success = proxyPrefetch.success || 0
  prefetchStats.skipped = proxyPrefetch.skipped || 0
  prefetchStats.staleTriggers = proxyPrefetch.stale_triggers || 0
  prefetchStats.lastAt = proxyPrefetch.last_at || ''
}

onMounted(async () => {
  const res = await getAlistConfigReq()
  for (const passwdInfo of res.data.passwdList) {
    passwdInfo.id = Math.random()
    if (Array.isArray(passwdInfo.encPath)) {
      passwdInfo.encPath = passwdInfo.encPath.join(',')
    } else if (typeof passwdInfo.encPath !== 'string') {
      passwdInfo.encPath = ''
    }
  }
  Object.assign(alistConfigForm, res.data)
  try {
    const schemeRes = await getSchemeConfigReq()
    if (schemeRes.data) {
      alistConfigForm.proxyH2c = schemeRes.data.enable_h2c || false
    }
  } catch (err) {
    console.error('Failed to load proxy H2C setting:', err)
  }
  await loadProxyDictionary()
  await loadProxyRouting()
  await refreshProbeStats()
  statsRefreshTimer.value = window.setInterval(() => {
    refreshProbeStats().catch(() => {})
  }, 10000)
})

onUnmounted(() => {
  if (statsRefreshTimer.value) {
    window.clearInterval(statsRefreshTimer.value)
    statsRefreshTimer.value = null
  }
})
</script>

<style scoped lang="scss">
.setting-alist-page {
  padding: 18px;
  color: #e8f0ff;
  font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
}

.setting-alist-shell {
  max-width: 1240px;
  margin: 0 auto;
  padding: 24px;
  border-radius: 24px;
  background: linear-gradient(180deg, rgba(34, 49, 73, 0.96) 0%, rgba(24, 37, 57, 0.96) 100%);
  box-shadow: 0 18px 48px rgba(3, 10, 24, 0.32);
}

.page-header {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  align-items: flex-start;
  margin-bottom: 24px;

  h3 {
    margin: 0 0 8px;
    font-size: 28px;
    font-weight: 700;
    color: #f4f7ff;
  }

  p {
    margin: 0;
    color: #aebfda;
    line-height: 1.7;
    font-size: 13px;
  }
}

.page-actions,
.footer-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.setting-collapse {
  border: none;
  background: transparent;
}

.section-banner {
  display: inline-flex;
  align-items: center;
  min-height: 42px;
  padding: 0 16px;
  border-radius: 12px;
  background: linear-gradient(135deg, #17335b 0%, #0f5a8b 100%);
  color: #f5f8ff;
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 0.02em;
}

.section-banner--accent {
  background: linear-gradient(135deg, #24569d 0%, #0f78aa 100%);
}

.section-body {
  padding: 18px 8px 12px;
  display: grid;
  gap: 18px;
}

.helper-text {
  margin-left: 12px;
  font-size: 12px;
  line-height: 1.7;
  color: #a8bbd8;
}

.helper-inline {
  margin-left: 12px;
  color: #bdd0eb;
  font-size: 12px;
}

.info-block {
  font-size: 12px;
  line-height: 1.9;
  color: #b3c6e3;
}

.metric-grid,
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}

.metric-card,
.summary-card,
.passwd-card,
.log-panel {
  border: 1px solid rgba(125, 154, 201, 0.18);
  border-radius: 16px;
  background: rgba(11, 20, 35, 0.42);
}

.metric-card,
.summary-card {
  padding: 16px;
}

.metric-card__title,
.summary-card__title {
  margin-bottom: 10px;
  color: #f4f7ff;
  font-size: 14px;
  font-weight: 700;
}

.metric-card__content,
.summary-card {
  color: #b8c9e4;
  font-size: 12px;
  line-height: 1.9;
}

.log-panel {
  margin-bottom: 16px;
}

.log-panel__header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
  padding: 14px 16px;
  border-bottom: 1px solid rgba(125, 154, 201, 0.15);
}

.log-panel__body {
  padding: 14px 16px 18px;
}

.empty-log {
  color: #9fb2cf;
  font-size: 12px;
}

.record-item {
  padding: 10px 0;
  border-bottom: 1px dashed rgba(173, 190, 216, 0.16);
  color: #bbcae4;
  font-size: 12px;
  line-height: 1.85;
}

.record-tag {
  margin-left: 8px;
  color: #90bbe8;
}

.passwd-list {
  display: grid;
  gap: 14px;
}

.passwd-card {
  padding: 16px;
}

.passwd-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  color: #f4f7ff;
}

.footer-actions {
  margin-top: 18px;
}

:deep(.el-collapse-item__header) {
  height: auto;
  line-height: normal;
  padding: 0;
  border: none;
  background: transparent;
}

:deep(.el-collapse-item__wrap) {
  border: none;
  background: transparent;
}

:deep(.el-collapse-item__content) {
  padding-bottom: 8px;
}

:deep(.el-form-item) {
  margin-bottom: 18px;
  align-items: flex-start;
}

:deep(.el-form-item__content) {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px 12px;
  line-height: 1.7;
}

:deep(.el-form-item__label) {
  color: #dce7fb;
  font-weight: 600;
}

:deep(.el-input__wrapper),
:deep(.el-textarea__inner) {
  background: rgba(8, 16, 29, 0.72);
  box-shadow: inset 0 0 0 1px rgba(126, 156, 205, 0.18);
}

:deep(.el-input__inner),
:deep(.el-textarea__inner),
:deep(.el-radio__label),
:deep(.el-checkbox__label) {
  color: #eef4ff;
}

:deep(.el-pagination) {
  margin-top: 14px;
  justify-content: flex-end;
}

@media (max-width: 900px) {
  .page-header {
    flex-direction: column;
  }

  .setting-alist-shell {
    padding: 18px;
  }

  .section-body {
    padding: 16px 0 8px;
  }
}
</style>
