import { defineConfig } from 'vitest/config'
import path from 'path'
import viteDefaults from './vite.config.js'

// 让 vitest 复用应用的插件链（unplugin-vue-components + ElementPlusResolver、
// unplugin-auto-import 等），保证测试里 <el-xxx> 组件与 ElMessage 等按需解析
// 与生产构建行为一致，避免“整包 app.use(ElementPlus)”作为隐性全局依赖。
const viteConfig = typeof viteDefaults === 'function' ? viteDefaults({ command: 'serve', mode: 'build' }) : viteDefaults

export default defineConfig({
  // 组件（unplugin-vue-components + ElementPlusResolver）仅在构建时启用：
  // 测试里 <el-*> 由 @vue/test-utils 的 stubs 直接替代，非按需解析的开销。
  plugins: (viteConfig.plugins || []).filter((plugin) => plugin?.name !== 'unplugin-vue-components'),
  resolve: viteConfig.resolve,
  define: viteConfig.define,
  base: viteConfig?.base,
  test: {
    clearMocks: true,
    environment: 'jsdom',
    // 让 vitest 内联 element-plus，按需样式（es/components/*/style/css）才会走 Vite 转换
    server: {
      deps: {
        inline: [/element-plus/]
      }
    },
    // setup 文件的路径。它们将运行在每个测试文件之前。
    setupFiles: ['./vitest.setup.js'],
    coverage: {
      provider: 'v8'
    }
  }
})
