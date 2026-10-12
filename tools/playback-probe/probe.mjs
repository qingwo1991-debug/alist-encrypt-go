// No media/network dependencies: only the caller-supplied HTMLVideoElement is used.
export const METRIC_SEMANTICS = Object.freeze({
  firstRenderedFrameMs: 'requestVideoFrameCallback metadata.presentationTime minus performance.now() immediately before src assignment/load/play for a user-initiated open. presentationTime is compositor submission, not physical display/photons. Only finite nonnegative deltas from this operation qualify, after loadedmetadata with currentSrc equal to the requested URL; metadata events themselves never count as frames.',
  seekRenderedFrameMs: 'requestVideoFrameCallback metadata.presentationTime minus performance.now() immediately before currentTime assignment. Requires seeked, seeking=false, a new presentedFrames value beyond the pre-seek baseline, presentationTime >= seek start, and mediaTime within targetToleranceSeconds of the requested target. This is compositor submission, not physical display/photons.',
  percentiles: 'Nearest-rank p50/p95, computed independently per metric and user-selected cacheCondition. Include only status=success and finite nonnegative values; unsupported/failure/cancelled and different metrics/conditions never contribute.',
  cacheCondition: 'User annotation only: cold/warm/consecutive. The tool does not clear or verify browser/server caches and does not automatically repeat or fetch URLs.',
});

export function sanitizeURL(value) {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return '[redacted non-http URL]';
    return `${url.protocol}//${url.host}/[redacted]`;
  } catch { return '[invalid URL]'; }
}

export function quantiles(values) {
  const sorted = values.filter(value => Number.isFinite(value) && value >= 0).sort((a, b) => a - b);
  const rank = p => sorted.length ? sorted[Math.ceil(p * sorted.length) - 1] : null;
  return { count: sorted.length, p50: rank(0.5), p95: rank(0.95) };
}

export function summarize(samples) {
  const result = {};
  for (const condition of ['cold', 'warm', 'consecutive']) {
    result[condition] = {};
    for (const metric of ['firstRenderedFrameMs', 'seekRenderedFrameMs']) {
      result[condition][metric] = quantiles(samples.filter(s => s.status === 'success' && s.cacheCondition === condition && s.metric === metric).map(s => s[metric]));
    }
  }
  return result;
}

export class PlaybackProbe {
  constructor(video, { now = () => performance.now(), setTimer = setTimeout, clearTimer = clearTimeout, timeoutMs = 15000, targetToleranceSeconds = 0.25, onChange = () => {} } = {}) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isFinite(targetToleranceSeconds) || targetToleranceSeconds <= 0) throw new Error('Invalid timeout/tolerance');
    Object.assign(this, { video, now, setTimer, clearTimer, timeoutMs, targetToleranceSeconds, onChange });
    this.samples = [];
    this.generation = 0;
    this.pending = null;
    this.frameId = null;
    this.lastPresentedFrames = 0;
    this.disposed = false;
    this.source = '';
  }

  _clear() {
    if (this.frameId !== null && typeof this.video.cancelVideoFrameCallback === 'function') this.video.cancelVideoFrameCallback(this.frameId);
    this.frameId = null;
    if (this.pending) {
      this.clearTimer(this.pending.timer);
      this.video.removeEventListener('seeked', this.pending.onSeeked);
      this.video.removeEventListener('error', this.pending.onError);
      this.video.removeEventListener('loadedmetadata', this.pending.onMetadata);
    }
  }

  _finish(status, reason, presentationTime) {
    const pending = this.pending;
    if (!pending) return;
    this._clear();
    this.pending = null;
    const sample = { ...pending.sample, status, reason };
    if (status === 'success') sample[sample.metric] = presentationTime - pending.start;
    this.samples.push(sample);
    this.onChange(sample);
  }

  _invalidate(reason) {
    ++this.generation;
    this._finish('cancelled', reason);
    this._clear();
  }

  _begin(metric, cacheCondition, targetSeconds) {
    if (this.disposed) throw new Error('Probe disposed');
    if (!['cold', 'warm', 'consecutive'].includes(cacheCondition)) throw new Error('Invalid cache condition');
    this._invalidate('superseded by a new operation');
    const generation = this.generation;
    const sample = { metric, cacheCondition, sanitizedURL: sanitizeURL(this.source), ...(targetSeconds === undefined ? {} : { targetSeconds }), targetToleranceSeconds: this.targetToleranceSeconds };
    const pending = { sample, start: this.now(), baseline: this.lastPresentedFrames, seeked: false, sourceReady: metric !== 'firstRenderedFrameMs' };
    this.pending = pending;
    pending.onMetadata = () => {
      if (generation === this.generation && this.video.currentSrc === new URL(this.source).href) pending.sourceReady = true;
    };
    this.video.addEventListener('loadedmetadata', pending.onMetadata);
    pending.onSeeked = () => { if (generation === this.generation) pending.seeked = true; };
    pending.onError = () => { if (generation === this.generation) this._finish('failure', 'media element error (URL/details omitted)'); };
    this.video.addEventListener('seeked', pending.onSeeked);
    this.video.addEventListener('error', pending.onError);
    pending.timer = this.setTimer(() => {
      if (generation === this.generation) this._finish('failure', 'rendered-frame timeout');
    }, this.timeoutMs);
    if (typeof this.video.requestVideoFrameCallback !== 'function' || typeof this.video.cancelVideoFrameCallback !== 'function') {
      this._finish('unsupported', 'requestVideoFrameCallback/cancelVideoFrameCallback unavailable; media events are not rendered frames');
      return generation;
    }
    const receive = (callbackNow, metadata) => {
      if (generation !== this.generation || this.pending !== pending) return;
      this.frameId = null;
      const validTimestamp = Number.isFinite(metadata.presentationTime) && metadata.presentationTime >= pending.start && metadata.presentationTime <= callbackNow;
      const validCounter = Number.isFinite(metadata.presentedFrames) && metadata.presentedFrames > pending.baseline;
      const atTarget = metric !== 'seekRenderedFrameMs' || (pending.seeked && !this.video.seeking && Number.isFinite(metadata.mediaTime) && Math.abs(metadata.mediaTime - targetSeconds) <= this.targetToleranceSeconds);
      if (pending.sourceReady && validTimestamp && validCounter && atTarget) {
        this.lastPresentedFrames = metadata.presentedFrames;
        this._finish('success', 'compositor presentation observed', metadata.presentationTime);
      } else {
        this.frameId = this.video.requestVideoFrameCallback(receive);
      }
    };
    this.frameId = this.video.requestVideoFrameCallback(receive);
    return generation;
  }

  open(url, cacheCondition = 'cold') {
    if (this.disposed) throw new Error('Probe disposed');
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Enter an authorized HTTP(S) media URL');
    this._invalidate('new source opened');
    // Abort the old resource before registering a callback for the new one.
    this.video.pause();
    this.video.removeAttribute('src');
    this.video.load();
    this.source = url;
    this.lastPresentedFrames = 0;
    const generation = this._begin('firstRenderedFrameMs', cacheCondition);
    try {
      if (this.pending) this.pending.start = this.now();
      this.video.src = url;
      this.video.load();
      const promise = this.video.play();
      promise?.catch(() => {
        if (generation === this.generation) this._finish('failure', 'play rejected (autoplay policy or media support; details omitted)');
      });
    } catch { this._finish('failure', 'open/load/play failed (details omitted)'); }
  }

  seek(targetSeconds, cacheCondition = 'consecutive') {
    if (!Number.isFinite(targetSeconds) || targetSeconds < 0) throw new Error('Seek target must be finite and nonnegative');
    if (!this.source) throw new Error('Open a media URL first');
    const generation = this._begin('seekRenderedFrameMs', cacheCondition, targetSeconds);
    if (this.pending && (!Number.isFinite(this.video.duration) || targetSeconds >= this.video.duration || Math.abs(this.video.currentTime - targetSeconds) < this.targetToleranceSeconds)) {
      this._finish('failure', 'seek requires finite duration and a different target strictly before end');
      return;
    }
    try {
      if (this.pending) this.pending.start = this.now();
      this.video.currentTime = targetSeconds;
      const promise = this.video.play();
      promise?.catch(() => { if (generation === this.generation) this._finish('failure', 'play rejected during seek (details omitted)'); });
    } catch { this._finish('failure', 'currentTime assignment/play failed (details omitted)'); }
  }

  stop() {
    this._invalidate('user stopped');
    this.video.pause();
    this.video.removeAttribute('src');
    this.video.load();
    this.source = '';
  }

  dispose() {
    this.stop();
    this.disposed = true;
  }

  export(environment = {}) {
    // Whitelist environment: do not accept arbitrary application/location data.
    return {
      schema_version: 1,
      metricSemantics: METRIC_SEMANTICS,
      environment: {
        userAgent: String(environment.userAgent || ''),
        platform: String(environment.platform || ''),
        language: String(environment.language || ''),
        secureContext: Boolean(environment.secureContext),
        requestVideoFrameCallback: typeof this.video.requestVideoFrameCallback === 'function',
        cancelVideoFrameCallback: typeof this.video.cancelVideoFrameCallback === 'function',
        timeoutMs: this.timeoutMs,
        targetToleranceSeconds: this.targetToleranceSeconds,
      },
      samples: this.samples.map(sample => ({ ...sample })),
      summary: summarize(this.samples),
    };
  }
}
