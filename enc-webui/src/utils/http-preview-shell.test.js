// @vitest-environment node
import { readFileSync } from 'node:fs'
import { URL as FileURL } from 'node:url'
import { JSDOM } from 'jsdom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const source = readFileSync(new FileURL('../../../internal/handler/assets/preview-shell.js', import.meta.url), 'utf8')
let dom
let win
let document
let timers
let nextTimer
let fetchMock
let nativePushState
const shell = () => document.querySelector('.aeg-preview-shell')
const flush = async () => { await Promise.resolve(); await Promise.resolve() }
const navigate = path => win.history.pushState({}, '', path)

beforeEach(() => {
  dom = new JSDOM('<div id="root"><div class="obj-box"><a href="/folder/a.mp4">Video</a></div></div>', {
    url: 'http://openlist.test/folder/', runScripts: 'outside-only'
  })
  win = dom.window
  document = win.document
  timers = new Map()
  nextTimer = 0
  win.setTimeout = callback => { timers.set(++nextTimer, callback); return nextTimer }
  win.clearTimeout = id => timers.delete(id)
  win.HTMLElement.prototype.getClientRects = function () { return this.dataset.hidden ? [] : [{}] }
  fetchMock = vi.fn(() => new Promise(() => {}))
  win.fetch = fetchMock
  nativePushState = win.history.pushState.bind(win.history)
  win.eval(source)
})

afterEach(() => dom.window.close())

function click(path = '/folder/a.mp4', options = {}) {
  const link = document.querySelector('a')
  link.href = path
  link.addEventListener('click', event => {
    event.preventDefault()
    if (!options.noNavigate) navigate(path)
  }, { once: true })
  link.dispatchEvent(new win.MouseEvent('click', { bubbles: true, button: 0, ...options }))
}

function player(parent = document.querySelector('.obj-box'), hidden = false) {
  const video = document.createElement('video')
  if (hidden) video.dataset.hidden = 'true'
  parent.append(video)
  return video
}

describe('OpenList HTTP preview feedback (exact embedded browser asset)', () => {
  it('shows a real 16:9 loading region synchronously before file details resolve, without fetching anything', async () => {
    click()
    expect(shell()).not.toBeNull()
    expect(shell().getAttribute('aria-busy')).toBe('true')
    expect(shell().nextSibling.className).toBe('obj-box')
    await flush()
    expect(shell()).not.toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
    expect(document.querySelector('video')).toBeNull()
  })

  it('does not alter media, hide upstream content or remove feedback merely because details settled', async () => {
    click()
    await flush()
    document.querySelector('.obj-box').append(document.createElement('div'))
    await flush()
    expect(shell()).not.toBeNull()
    expect(document.querySelector('.obj-box').getAttribute('style')).toBeNull()
    const video = player()
    await flush()
    expect(shell()).toBeNull()
    expect(video.getAttribute('src')).toBeNull()
    expect(timers.size).toBe(0)
  })

  it('ignores a previous player and hidden new players, then hands over to the visible new player', async () => {
    const old = player()
    click()
    await flush()
    expect(shell()).not.toBeNull()
    const next = player(undefined, true)
    await flush()
    expect(shell()).not.toBeNull()
    delete next.dataset.hidden
    next.className = 'ready'
    await flush()
    expect(shell()).toBeNull()
    expect(old.isConnected).toBe(true)
  })

  it('reattaches feedback when Solid replaces the content box', async () => {
    click()
    const replacement = document.createElement('div')
    replacement.className = 'obj-box'
    document.querySelector('.obj-box').replaceWith(replacement)
    await flush()
    expect(shell().nextSibling).toBe(replacement)
    player(replacement)
    await flush()
    expect(shell()).toBeNull()
  })

  it('supports router-only grid, keyboard and double-click navigation', async () => {
    navigate('/folder/grid.mkv')
    expect(shell()).not.toBeNull()
    await flush()
    expect(shell()).not.toBeNull()
    navigate('/folder/')
    expect(shell()).toBeNull()
  })

  it('shows feedback when browser history enters a video, and clears when it returns to a directory', async () => {
    nativePushState({}, '', '/folder/a.mp4')
    win.dispatchEvent(new win.PopStateEvent('popstate'))
    expect(shell()).not.toBeNull()
    await flush()
    nativePushState({}, '', '/folder/')
    win.dispatchEvent(new win.PopStateEvent('popstate'))
    expect(shell()).toBeNull()
  })

  it('keeps only the newest navigation and does not leave an old timeout able to clear it', async () => {
    click()
    const oldTimer = Array.from(timers.values())[0]
    navigate('/folder/b.mp4')
    await flush()
    expect(document.querySelectorAll('.aeg-preview-shell')).toHaveLength(1)
    expect(timers.size).toBe(1)
    oldTimer()
    expect(shell()).not.toBeNull()
    navigate('/folder/')
    expect(shell()).toBeNull()
    expect(timers.size).toBe(0)
  })

  it.each([
    ['modified', '/folder/a.mp4', { ctrlKey: true }],
    ['cross-origin', 'https://elsewhere.test/a.mp4', {}],
    ['download API', '/d/a.mp4', {}],
    ['WebDAV', '/dav/a.mp4', {}],
    ['management', '/@manage/a.mp4', {}],
    ['ordinary directory', '/folder/subfolder/', {}],
    ['text', '/folder/a.txt', {}]
  ])('does not show for %s clicks', async (_name, path, options) => {
    click(path, { ...options, noNavigate: true })
    await flush()
    expect(shell()).toBeNull()
  })

  it('cancels non-navigation clicks, Escape and close without interfering with normal application UI', async () => {
    click('/folder/a.mp4', { noNavigate: true })
    await flush()
    expect(shell()).toBeNull()
    navigate('/folder/a.mp4')
    win.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }))
    expect(shell()).toBeNull()
    navigate('/folder/b.mp4')
    shell().querySelector('button').click()
    expect(shell()).toBeNull()
    expect(document.querySelector('.obj-box')).not.toBeNull()
  })

  it('restores the original page after a bounded timeout or page unload', () => {
    navigate('/folder/a.mp4')
    Array.from(timers.values())[0]()
    expect(shell()).toBeNull()
    navigate('/folder/b.mp4')
    win.dispatchEvent(new win.Event('pagehide'))
    expect(shell()).toBeNull()
    expect(timers.size).toBe(0)
  })

  it('does not read or wrap fetch/XHR, storage or credentials, and installs once', () => {
    const fetch = win.fetch
    const open = win.XMLHttpRequest.prototype.open
    const history = win.history.pushState
    win.eval(source)
    expect(win.fetch).toBe(fetch)
    expect(win.XMLHttpRequest.prototype.open).toBe(open)
    expect(win.history.pushState).toBe(history)
    expect(source).not.toMatch(/localStorage|sessionStorage|\.cookie|Authorization|innerHTML|\.json\(/)
  })
})
