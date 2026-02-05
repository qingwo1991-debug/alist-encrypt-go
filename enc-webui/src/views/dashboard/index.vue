<template>
  <div class="scroll-y">
    <div v-lang class="mt-10px mb-10px font-bold">主题切换</div>
    <el-button @click="setTheme('lighting-theme')">lighting-theme</el-button>
    <el-button @click="setTheme('dark')">dark-theme</el-button>

    <!-- <el-button @click="setTheme('base-theme')">base-theme(default)</el-button>
    <el-button @click="setTheme('lighting-theme')">lighting-theme</el-button>
    <el-button @click="setTheme('china-red')">china-red(default)</el-button>
    <el-button @click="setTheme('dark')">dark-theme</el-button> -->

    <div v-lang class="mt-10px mb-10px font-bold">switch language</div>
    <el-button @click="changeLanguage('en')">en</el-button>
    <el-button @click="changeLanguage('zh')">zh</el-button>

    <div v-lang class="mt-30px font-bold mb-10px">账号设置</div>
    <!--条件搜索-->
    <el-form ref="refSearchForm" :label-position="labelPosition" label-width="80px" :model="userForm">
      <el-form-item prop="username" label="用户名">
        <el-input v-model="userForm.username" style="max-width: 260px" placeholder="username" />
        <el-button type="primary" style="margin-left: 10px" @click="updateUsername">修改用户名</el-button>
      </el-form-item>
      <el-form-item prop="password" label="原密码">
        <el-input v-model="userForm.password" style="max-width: 260px" type="password" placeholder="password" />
      </el-form-item>
      <el-form-item prop="newpassword" label="新密码">
        <el-input v-model="userForm.newpassword" style="max-width: 260px" type="password" placeholder="password" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="updatePasswd">修改密码</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>
<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useConfigStore } from '@/store/config'
import { useBasicStore } from '@/store/basic'
import { upatePasswordReq, updateUsernameReq } from '@/api/user'
import { ElMessage } from 'element-plus'

const labelPosition = ref('right')
const router = useRouter()

const basicStore = useBasicStore()
const { settings, userInfo } = basicStore

const { setTheme, theme, setSize, size, setLanguage } = useConfigStore()
setSize('default')
// setTheme('dark')
const changeLanguage = (langParam) => {
  setLanguage(langParam)
}

const userForm = reactive({
  username: '',
  originalUsername: '', // Store original username for API call
  password: '',
  newpassword: ''
})
const refSearchForm = ref()
userForm.username = userInfo.username
userForm.originalUsername = userInfo.username

const updatePasswd = () => {
  if (!userForm.password) {
    ElMessage.error('请输入原密码')
    return
  }
  if (!userForm.newpassword) {
    ElMessage.error('请输入新密码')
    return
  }
  upatePasswordReq({
    username: userForm.originalUsername,
    password: userForm.password,
    newpassword: userForm.newpassword
  }).then((res) => {
    ElMessage.success('密码修改成功，请重新登录')
    basicStore.setToken('')
    router.push('/login')
  }).catch((err) => {
    ElMessage.error(err?.msg || '修改失败')
  })
}

const updateUsername = () => {
  if (!userForm.password) {
    ElMessage.error('请输入密码以验证身份')
    return
  }
  if (!userForm.username || userForm.username.length < 3) {
    ElMessage.error('用户名至少需要3个字符')
    return
  }
  if (userForm.username === userForm.originalUsername) {
    ElMessage.warning('用户名未变更')
    return
  }
  updateUsernameReq({
    username: userForm.originalUsername,
    password: userForm.password,
    newusername: userForm.username
  }).then((res) => {
    ElMessage.success('用户名修改成功，请重新登录')
    basicStore.setToken('')
    router.push('/login')
  }).catch((err) => {
    ElMessage.error(err?.msg || '修改失败')
  })
}

</script>
