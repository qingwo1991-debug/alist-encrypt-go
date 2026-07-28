import fs from 'node:fs'
import path from 'node:path'

const virtualModuleId = 'virtual:svg-icons-register'
const resolvedVirtualModuleId = `\0${virtualModuleId}`

function walkSvgFiles(directory) {
  const files = []
  const visit = (current) => {
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))
    for (const entry of entries) {
      const entryPath = path.join(current, entry.name)
      if (entry.isDirectory()) {
        visit(entryPath)
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.svg')) {
        files.push(entryPath)
      }
    }
  }
  visit(directory)
  return files
}

function quotedAttribute(attributes, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = attributes.match(new RegExp(`(?:^|\\s)${escapedName}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i'))
  return match ? (match[1] ?? match[2] ?? '') : ''
}

function numericDimension(attributes, name) {
  const value = quotedAttribute(attributes, name).trim()
  const match = value.match(/^([0-9]+(?:\.[0-9]+)?)(?:px)?$/i)
  return match ? match[1] : ''
}

export function compileSvgSymbol(source, symbolId, filename = '<svg>') {
  let svg = source
    .replace(/^\uFEFF/, '')
    .replace(/<\?xml[\s\S]*?\?>/gi, '')
    .replace(/<!DOCTYPE[\s\S]*?>/gi, '')
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, '')
    .trim()

  if (/<(?:script|foreignObject)\b|\son[a-z]+\s*=|javascript\s*:/i.test(svg)) {
    throw new Error(`Unsafe SVG content in ${filename}`)
  }

  const match = svg.match(/^<svg\b([^>]*)>([\s\S]*)<\/svg\s*>$/i)
  if (!match) {
    throw new Error(`Invalid SVG document in ${filename}`)
  }

  const attributes = match[1]
  let body = match[2]
    .replace(/\s+p-id\s*=\s*(?:"[^"]*"|'[^']*')/gi, '')
    .replace(/stroke\s*=\s*(?:"[a-zA-Z#0-9]*"|'[a-zA-Z#0-9]*')/g, 'stroke="currentColor"')

  let viewBox = quotedAttribute(attributes, 'viewBox').trim()
  if (!viewBox) {
    const width = numericDimension(attributes, 'width')
    const height = numericDimension(attributes, 'height')
    if (!width || !height) {
      throw new Error(`SVG is missing viewBox or numeric dimensions in ${filename}`)
    }
    viewBox = `0 0 ${width} ${height}`
  }

  const optionalAttributes = ['fill', 'stroke', 'stroke-width', 'preserveAspectRatio']
    .map((name) => [name, quotedAttribute(attributes, name).trim()])
    .filter(([, value]) => value !== '')
    .map(([name, value]) => `${name}=${JSON.stringify(value)}`)
    .join(' ')
  const suffix = optionalAttributes ? ` ${optionalAttributes}` : ''
  return `<symbol id=${JSON.stringify(symbolId)} viewBox=${JSON.stringify(viewBox)}${suffix}>${body}</symbol>`
}

function symbolIdFor(file, root, prefix) {
  const relative = path.relative(root, file).replace(/\\/g, '/').replace(/\.svg$/i, '')
  const normalized = relative
    .split('/')
    .map((part) => part.replace(/[^A-Za-z0-9_.-]/g, '-'))
    .join('-')
  return `${prefix}${normalized}`
}

export function buildSprite(iconDirs, symbolPrefix = 'icon-') {
  const symbols = new Map()
  const files = []
  for (const root of iconDirs) {
    for (const file of walkSvgFiles(root)) {
      files.push(file)
      const symbolId = symbolIdFor(file, root, symbolPrefix)
      // Preserve the old plugin's effective behavior for duplicate IDs: the
      // first icon directory wins when the DOM resolves #icon-name.
      if (!symbols.has(symbolId)) {
        symbols.set(symbolId, compileSvgSymbol(fs.readFileSync(file, 'utf8'), symbolId, file))
      }
    }
  }
  return { files, html: [...symbols.values()].join('') }
}

function registrationModule(html, domId) {
  return `
const spriteHtml = ${JSON.stringify(html)}
if (typeof document !== 'undefined') {
  const loadSprite = () => {
    let sprite = document.getElementById(${JSON.stringify(domId)})
    if (!sprite) {
      sprite = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
      sprite.id = ${JSON.stringify(domId)}
      sprite.setAttribute('aria-hidden', 'true')
      sprite.style.position = 'absolute'
      sprite.style.width = '0'
      sprite.style.height = '0'
      sprite.style.overflow = 'hidden'
      document.body.insertBefore(sprite, document.body.firstChild)
    }
    sprite.innerHTML = spriteHtml
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadSprite, { once: true })
  } else {
    loadSprite()
  }
}
export default {}
`
}

export function createSvgSpritePlugin({
  iconDirs,
  symbolPrefix = 'icon-',
  domId = '__openlist_svg_sprite__'
}) {
  const roots = iconDirs.map((directory) => path.resolve(directory))
  return {
    name: 'openlist-svg-sprite',
    enforce: 'pre',
    resolveId(id) {
      return id === virtualModuleId ? resolvedVirtualModuleId : null
    },
    load(id) {
      if (id !== resolvedVirtualModuleId) return null
      const { html } = buildSprite(roots, symbolPrefix)
      return registrationModule(html, domId)
    },
    buildStart() {
      for (const root of roots) {
        for (const file of walkSvgFiles(root)) this.addWatchFile(file)
      }
    },
    handleHotUpdate(context) {
      if (!roots.some((root) => context.file.startsWith(`${root}${path.sep}`))) return
      const module = context.server.moduleGraph.getModuleById(resolvedVirtualModuleId)
      if (module) {
        context.server.moduleGraph.invalidateModule(module)
        return [module]
      }
    }
  }
}
