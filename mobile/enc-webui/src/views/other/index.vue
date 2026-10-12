<template>
  <section class="playback-metrics-info">
    <h2>播放指标说明</h2>
    <p>本地播放记录请在应用设置 → 播放统计中查看。</p>
    <p>上游响应头（header_latency_ms）：上游请求至响应头就绪，不是播放器真实首帧。</p>
    <p>服务端正文首字节（first_byte_latency_ms）：handler 开始至首次成功正文写入，也不是播放器真实首帧。</p>
    <p>当前移动端代理未导出正文首字节指标；未测量的字段显示为未知，不以历史响应头数据补齐。</p>
    <p>播放器真实首帧需要独立仪表测试页面采集实际渲染事件，不能由上述服务端指标推导。</p>
  </section>
</template>

<script setup lang="ts"></script>

<style scoped lang="scss">
.playback-metrics-info {
  padding: 24px;
  line-height: 1.8;
}
</style>
