import test from 'node:test';
import assert from 'node:assert/strict';
import { PlaybackProbe, quantiles, summarize, sanitizeURL } from './probe.mjs';

class Video extends EventTarget {
  constructor() {
    super();
    this.callbacks = new Map();
    this.cancelled = [];
    this.nextId = 0;
    this.currentTime = 0;
    this.duration = 100;
    this.seeking = false;
    this.src = '';
    this.currentSrc = '';
  }
  requestVideoFrameCallback(callback) { this.callbacks.set(++this.nextId, callback); return this.nextId; }
  cancelVideoFrameCallback(id) { this.cancelled.push(id); this.callbacks.delete(id); }
  pause() {}
  load() { if (!this.src) this.currentSrc = ''; }
  play() { return Promise.resolve(); }
  removeAttribute(name) { if (name === 'src') this.src = ''; }
  metadata() { this.currentSrc = this.src; this.emit('loadedmetadata'); }
  emit(name) { this.dispatchEvent(new Event(name)); }
  frame(presentationTime, mediaTime = 0, presentedFrames = 1) {
    const [id, callback] = this.callbacks.entries().next().value;
    this.callbacks.delete(id);
    callback(presentationTime + 1, { presentationTime, mediaTime, presentedFrames });
  }
}
function setup() {
  const video = new Video();
  const timers = new Map();
  let clock = 100;
  let timerId = 0;
  const probe = new PlaybackProbe(video, {
    now: () => clock,
    setTimer: callback => { timers.set(++timerId, callback); return timerId; },
    clearTimer: id => timers.delete(id),
  });
  return { video, probe, timers, time: value => { clock = value; } };
}
const url = 'https://user:password@media.example/private/token/video.mp4?auth=secret#credential';
function opened(ctx) {
  ctx.probe.open(url);
  ctx.video.metadata();
  ctx.video.frame(120, 0, 1);
}

test('first frame uses presentationTime, never media events', () => {
  const ctx = setup();
  ctx.probe.open(url);
  for (const name of ['playing', 'loadeddata', 'seeked']) ctx.video.emit(name);
  assert.equal(ctx.probe.samples.length, 0);
  ctx.video.metadata();
  ctx.video.frame(135);
  assert.equal(ctx.probe.samples[0].firstRenderedFrameMs, 35);
  assert.equal(ctx.timers.size, 0);
});

test('old-source frames delivered to new callback cannot qualify before new metadata', () => {
  const ctx = setup();
  opened(ctx);
  ctx.time(200);
  ctx.probe.open('https://media.example/new.mp4');
  ctx.video.frame(210, 20, 100); // stale resource, delivered to NEW callback
  assert.equal(ctx.probe.samples.length, 1);
  ctx.video.currentSrc = url;
  ctx.video.emit('loadedmetadata');
  ctx.video.frame(215, 20, 101);
  assert.equal(ctx.probe.samples.length, 1);
  ctx.video.metadata();
  ctx.video.frame(225, 0, 1);
  assert.equal(ctx.probe.samples[1].firstRenderedFrameMs, 25);
});

test('generation and cancellation isolate open, seek, stop, dispose and late callbacks', () => {
  const ctx = setup();
  ctx.probe.open(url);
  const stale = [...ctx.video.callbacks.values()][0];
  ctx.time(200);
  ctx.probe.open(url);
  stale(230, { presentationTime: 220, presentedFrames: 99, mediaTime: 0 });
  assert.equal(ctx.probe.samples.length, 1);
  assert.equal(ctx.probe.samples[0].status, 'cancelled');
  assert.ok(ctx.video.cancelled.length);
  const stopped = [...ctx.video.callbacks.values()][0];
  ctx.probe.stop();
  stopped(250, { presentationTime: 240, presentedFrames: 100, mediaTime: 0 });
  assert.equal(ctx.probe.samples.length, 2);
  assert.equal(ctx.timers.size, 0);
  ctx.probe.dispose();
  ctx.probe.dispose();
  assert.throws(() => ctx.probe.open(url), /disposed/);
});

test('missing request/cancel API is unsupported, not loadeddata/playing success', () => {
  for (const api of ['requestVideoFrameCallback', 'cancelVideoFrameCallback']) {
    const ctx = setup();
    ctx.video[api] = undefined;
    ctx.probe.open(url);
    ctx.video.emit('loadeddata');
    ctx.video.emit('playing');
    assert.equal(ctx.probe.samples[0].status, 'unsupported');
    assert.equal(ctx.probe.samples[0].firstRenderedFrameMs, undefined);
    assert.equal(ctx.timers.size, 0);
    ctx.probe.seek(10);
    assert.equal(ctx.probe.samples[1].status, 'unsupported');
  }
});

test('seek rejects old time, counter, pre-start, pre-seeked and seeking frames', () => {
  const ctx = setup();
  opened(ctx);
  ctx.time(200);
  ctx.probe.seek(10);
  ctx.video.frame(205, 10, 2); // before seeked
  ctx.video.emit('seeked');
  ctx.video.frame(210, 0, 3); // stale time
  ctx.video.frame(215, 10, 1); // stale counter
  ctx.video.frame(190, 10, 4); // pre-start timestamp
  ctx.video.seeking = true;
  ctx.video.frame(220, 10, 5);
  assert.equal(ctx.probe.samples.length, 1);
  ctx.video.seeking = false;
  ctx.video.frame(230, 10.2, 6);
  assert.equal(ctx.probe.samples[1].seekRenderedFrameMs, 30);
  assert.equal(ctx.probe.samples[1].status, 'success');
});

test('seek times out with no valid frame, and obsolete timer cannot fail next operation', () => {
  const ctx = setup();
  opened(ctx);
  ctx.time(200);
  ctx.probe.seek(10);
  const timeout = [...ctx.timers.values()][0];
  ctx.video.emit('seeked');
  ctx.video.frame(210, 0, 2);
  timeout();
  assert.equal(ctx.probe.samples[1].status, 'failure');
  ctx.probe.seek(20);
  timeout();
  assert.equal(ctx.probe.samples.length, 2);
  [...ctx.timers.values()][0]();
  assert.equal(ctx.probe.samples[2].status, 'failure');
});

test('invalid and no-op seek targets fail without fabricated measurements', () => {
  const ctx = setup();
  opened(ctx);
  assert.throws(() => ctx.probe.seek(NaN), /finite/);
  ctx.probe.seek(0);
  assert.equal(ctx.probe.samples[1].status, 'failure');
  ctx.video.duration = Infinity;
  ctx.probe.seek(10);
  assert.equal(ctx.probe.samples[2].status, 'failure');
});

test('media errors and late play rejections do not leak or contaminate another session', async () => {
  const ctx = setup();
  let reject;
  ctx.video.play = () => new Promise((resolve, rejectPromise) => { reject = rejectPromise; });
  ctx.probe.open(url);
  const oldReject = reject;
  ctx.probe.open('https://media.example/other');
  oldReject(new Error(url));
  await Promise.resolve();
  assert.equal(ctx.probe.samples.length, 1);
  ctx.video.emit('error');
  assert.equal(ctx.probe.samples[1].status, 'failure');
  reject(new Error(url));
  await Promise.resolve();
  assert.equal(ctx.probe.samples.length, 2);
  assert.ok(!JSON.stringify(ctx.probe.export()).includes('password'));
});

test('nearest rank quantiles filter invalid values and summaries isolate status/metric/condition', () => {
  assert.deepEqual(quantiles([]), { count: 0, p50: null, p95: null });
  assert.deepEqual(quantiles([100, 0, 10, NaN, Infinity, -1, null]), { count: 3, p50: 10, p95: 100 });
  assert.deepEqual(quantiles(Array.from({ length: 20 }, (_, i) => i + 1)), { count: 20, p50: 10, p95: 19 });
  const sample = (metric, cacheCondition, status, value) => ({ metric, cacheCondition, status, [metric]: value });
  const summary = summarize([
    sample('firstRenderedFrameMs', 'cold', 'success', 10),
    sample('firstRenderedFrameMs', 'cold', 'failure', 999),
    sample('firstRenderedFrameMs', 'cold', 'unsupported', 888),
    sample('firstRenderedFrameMs', 'cold', 'cancelled', 777),
    sample('firstRenderedFrameMs', 'cold', 'success', -1),
    sample('firstRenderedFrameMs', 'cold', 'success', NaN),
    sample('firstRenderedFrameMs', 'warm', 'success', 100),
    sample('seekRenderedFrameMs', 'cold', 'success', 20),
  ]);
  assert.deepEqual(summary.cold.firstRenderedFrameMs, { count: 1, p50: 10, p95: 10 });
  assert.equal(summary.cold.seekRenderedFrameMs.p50, 20);
  assert.equal(summary.warm.firstRenderedFrameMs.p50, 100);
  assert.equal(summary.consecutive.firstRenderedFrameMs.count, 0);
});

test('export schema, environment whitelist and URL redaction omit credentials/query/path/fragment', () => {
  const ctx = setup();
  opened(ctx);
  const report = ctx.probe.export({ userAgent: 'stub browser', platform: 'stub', language: 'en', secureContext: true, location: url, arbitrary: url });
  assert.equal(report.schema_version, 1);
  assert.equal(report.samples[0].sanitizedURL, 'https://media.example/[redacted]');
  assert.equal(report.environment.location, undefined);
  assert.ok(report.metricSemantics.firstRenderedFrameMs.includes('presentationTime'));
  const json = JSON.stringify(report);
  for (const secret of ['password', 'user:', 'private', 'token', 'auth=', 'secret', '#credential']) assert.ok(!json.includes(secret), secret);
  assert.equal(sanitizeURL('file:///secret'), '[redacted non-http URL]');
  assert.equal(sanitizeURL('not a URL'), '[invalid URL]');
});
