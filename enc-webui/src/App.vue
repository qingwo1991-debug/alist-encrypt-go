<template>
  <el-config-provider :locale="lang[language]" namespace="el" :size="elSize">
    <router-view />
  </el-config-provider>
</template>

<script setup lang="ts" name="App">
import { computed, onBeforeMount, onMounted } from 'vue'
//element-plus lang
import zh from 'element-plus/es/locale/lang/zh-cn'
import en from 'element-plus/es/locale/lang/en'
import { storeToRefs } from 'pinia/dist/pinia'
import { useBasicStore } from '@/store/basic'
import { useConfigStore } from '@/store/config'
import { useErrorLog } from '@/hooks/use-error-log'

//reshow default setting
import { toggleHtmlClass } from '@/theme/utils'
const lang = { zh, en }

const { settings } = storeToRefs(useBasicStore())
const { size, language } = storeToRefs(useConfigStore())
// ElConfigProvider 的 size 是 'large'|'default'|'small' 联合类型，配置里是 string，
// 在脚本侧收窄以满足模板 props 类型检查。
const elSize = computed(() => (size.value as 'large' | 'default' | 'small'))
onBeforeMount(() => {
  //set tmp token when setting isNeedLogin false
  if (!settings.value.isNeedLogin) useBasicStore().setToken(settings.value.tmpToken)
})
onMounted(() => {
  //lanch the errorLog collection
  useErrorLog()
})
onMounted(() => {
  const { setTheme, theme, setSize, size, setLanguage, language } = useConfigStore()
  setTheme(theme)
  setLanguage(language)
  setSize(size)
  toggleHtmlClass(theme)
})
</script>
<style lang="scss">
//修改进度条样式
#nprogress .bar {
  background: var(--pregress-bar-color) !important;
}
</style>
