// OpenList preview feedback only. Never fetch metadata/media or manufacture a
// media URL/size here: the upstream application remains the authority for both.
(() => {
  'use strict';
  if (window.__aegPreviewShell) return;
  window.__aegPreviewShell = true;
  const selector = '.artplayer-app, video';
  const videoPath = /\.(?:mp4|m4v|mkv|webm|mov|avi|flv|ts|m2ts|mts|mpeg|mpg|wmv|3gp|ogv)$/i;
  let active = null;

  function route(value) {
    try {
      const url = new URL(value, location.href);
      if (url.origin !== location.origin || !/^https?:$/.test(url.protocol)) return null;
      if (/^\/(?:@|api(?:\/|$)|enc-api(?:\/|$)|d\/|p\/|dav(?:\/|$)|__aeg\/)/.test(url.pathname)) return null;
      return url;
    } catch { return null; }
  }

  function isVideo(url) {
    try { return videoPath.test(decodeURIComponent(url.pathname)); } catch { return false; }
  }

  function stop() {
    if (!active) return;
    const previous = active;
    active = null;
    clearTimeout(previous.timer);
    previous.observer.disconnect();
    previous.shell.remove();
  }

  function visible(node) {
    return node.isConnected && node.getClientRects().length > 0 &&
      getComputedStyle(node).visibility !== 'hidden' && getComputedStyle(node).display !== 'none';
  }

  function refresh() {
    const state = active;
    if (!state) return;
    const current = route(location.href);
    if (!current || current.pathname !== state.target.pathname || current.search !== state.target.search) {
      // During click capture the router has not run yet. A microtask below
      // finishes this grace period; later navigation must never keep stale UI.
      if (state.navigated) stop();
      return;
    }
    state.navigated = true;
    const box = document.querySelector('#root .obj-box');
    if (!box) return;
    for (const node of box.querySelectorAll(selector)) {
      if ((!state.players.has(node) || state.players.get(node) !== node.getAttribute('src')) && visible(node)) {
        stop();
        return;
      }
    }
    // A sibling, not a managed child of Solid's content box. Do not hide or
    // restyle application nodes: that would hide the real player as it mounts.
    if (state.shell.nextSibling !== box) box.before(state.shell);
  }

  function start(target) {
    stop();
    const shell = document.createElement('section');
    shell.className = 'aeg-preview-shell';
    shell.setAttribute('role', 'status');
    shell.setAttribute('aria-live', 'polite');
    shell.setAttribute('aria-busy', 'true');
    const message = document.createElement('span');
    message.textContent = '正在准备播放器…';
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = '关闭加载提示';
    close.addEventListener('click', stop);
    shell.append(message, close);
    const observer = new MutationObserver(refresh);
    const players = new Map(Array.from(document.querySelectorAll(selector), node => [node, node.getAttribute('src')]));
    const state = { target, shell, players, observer, navigated: false, timer: null };
    active = state;
    // Bounded and fail-open: denied details, failed chunks or an unsupported
    // upstream theme must restore the untouched application, never cover it.
    state.timer = setTimeout(() => { if (active === state) stop(); }, 10000);
    observer.observe(document.getElementById('root'), { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'class', 'style'] });
    const box = document.querySelector('#root .obj-box');
    if (box) box.before(shell);
    queueMicrotask(() => {
      if (active !== state) return;
      state.navigated = true;
      refresh();
    });
  }

  document.addEventListener('click', event => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    if (!(event.target instanceof Element)) return;
    const link = event.target.closest('a[href]');
    if (!link || !link.closest('#root .obj-box') || link.hasAttribute('download') ||
      (link.target && link.target !== '_self') ||
      event.target.closest('button, input, select, textarea, [role="checkbox"]')) return;
    const target = route(link.href);
    if (target && isVideo(target) && target.href !== location.href) start(target);
  }, true);

  // The expected source -> target pushState is not cancellation. Check the
  // resulting URL instead, preserving return values, exceptions and `this`.
  for (const method of ['pushState', 'replaceState']) {
    const original = history[method];
    history[method] = function (...args) {
      const before = location.href;
      const result = Reflect.apply(original, this, args);
      const target = route(location.href);
      // Covers grid, keyboard, double-click mode, and the router's own
      // directory-relative links without guessing how it resolves their href.
      if (target && target.href !== before && isVideo(target) && document.querySelector('#root .obj-box') &&
        (!active || active.target.href !== target.href)) start(target);
      refresh();
      return result;
    };
  }
  window.addEventListener('popstate', () => {
    const target = route(location.href);
    if (target && isVideo(target) && document.querySelector('#root .obj-box') &&
      (!active || active.target.href !== target.href)) start(target);
    refresh();
  });
  window.addEventListener('hashchange', refresh);
  window.addEventListener('pagehide', stop);
  window.addEventListener('keydown', event => { if (event.key === 'Escape') stop(); });
})();
