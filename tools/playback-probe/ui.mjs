import { PlaybackProbe } from './probe.mjs';

const element = id => document.getElementById(id);
const environment = () => ({
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  language: navigator.language,
  secureContext: window.isSecureContext,
});
const probe = new PlaybackProbe(element('video'), {
  onChange(sample) {
    element('status').textContent = `${sample.metric}: ${sample.status} — ${sample.reason}`;
    element('results').textContent = JSON.stringify(probe.export(environment()), null, 2);
  },
});
const action = callback => {
  try { callback(); }
  catch { element('status').textContent = '操作无效：请输入授权 HTTP(S) URL 或有效 seek 目标；错误详情不导出，以免泄露 URL。'; }
};
element('open').addEventListener('click', () => action(() => {
  element('status').textContent = '等待真正的首帧 callback（最多 15 秒）…';
  probe.open(element('url').value.trim(), element('condition').value);
}));
element('seek').addEventListener('click', () => action(() => {
  element('status').textContent = '等待目标位置的新帧 callback（最多 15 秒）…';
  const value = element('target').value.trim();
  if (!value) throw new Error('Missing target');
  probe.seek(Number(value), element('condition').value);
}));
element('stop').addEventListener('click', () => action(() => {
  probe.stop();
  element('status').textContent = '已停止，旧 callback 不会污染新样本。';
}));
element('download').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(probe.export(environment()), null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'playback-probe.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
window.addEventListener('pagehide', () => probe.dispose(), { once: true });
