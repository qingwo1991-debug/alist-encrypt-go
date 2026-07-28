import assert from 'node:assert/strict'
import test from 'node:test'

import { compileSvgSymbol } from './vite-svg-sprite-plugin.mjs'

test('compiles a local SVG without retaining external document metadata', () => {
  const source = `<?xml version="1.0"?><!DOCTYPE svg PUBLIC "x" "https://example.invalid/svg.dtd">
    <svg width="128" height="64" xmlns="http://www.w3.org/2000/svg">
      <defs><style>@font-face { src: url(https://example.invalid/font.woff) }</style></defs>
      <path p-id="123" stroke="#fff" d="M0 0h1" />
    </svg>`
  const symbol = compileSvgSymbol(source, 'icon-safe')
  assert.match(symbol, /^<symbol id="icon-safe" viewBox="0 0 128 64">/)
  assert.match(symbol, /stroke="currentColor"/)
  assert.doesNotMatch(symbol, /DOCTYPE|example\.invalid|p-id/)
})

test('rejects active SVG content', () => {
  assert.throws(
    () => compileSvgSymbol('<svg viewBox="0 0 1 1"><script>alert(1)</script></svg>', 'icon-bad'),
    /Unsafe SVG content/
  )
  assert.throws(
    () => compileSvgSymbol('<svg viewBox="0 0 1 1"><path onclick="alert(1)" /></svg>', 'icon-bad'),
    /Unsafe SVG content/
  )
})
