import { createRouter, createWebHashHistory } from 'vue-router'

import Layout from '@/layout/index.vue'

export const constantRoutes = [
  {
    path: '/redirect',
    component: Layout,
    hidden: true,
    children: [
      {
        path: '/redirect/:path(.*)',
        component: () => import('@/views/redirect')
      }
    ]
  },

  {
    path: '/login',
    component: () => import('@/views/login/index.vue'),
    hidden: true
  },
  {
    path: '/404',
    component: () => import('@/views/error-page/404.vue'),
    hidden: true
  },
  {
    path: '/401',
    component: () => import('@/views/error-page/401.vue'),
    hidden: true
  },

  // ── 总览组 ──────────────────────────────
  {
    path: '/overview',
    component: Layout,
    redirect: '/overview/dashboard',
    meta: { title: 'Overview', icon: 'monitor' },
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/index.vue'),
        meta: { title: 'Dashboard', elSvgIcon: 'Fold', affix: true }
      },
      {
        path: 'warm',
        name: 'warm-overview',
        component: () => import('@/views/warm-overview/index.vue'),
        meta: { title: 'warm overview', icon: 'sunrise' }
      },
      {
        path: 'stats',
        name: 'other',
        component: () => import('@/views/other/index.vue'),
        meta: { title: 'Stats', icon: 'chart' }
      }
    ]
  },

  // ── 配置组 ──────────────────────────────
  {
    path: '/config',
    component: Layout,
    redirect: '/config/alist',
    meta: { title: 'Config', icon: 'setting' },
    children: [
      {
        path: 'alist',
        name: 'alist',
        component: () => import('@/views/setting-alist/index.vue'),
        meta: { title: 'Setting alist', icon: 'form' }
      },
      {
        path: 'webdav',
        name: 'webdav',
        component: () => import('@/views/setting-webdav/index.vue'),
        meta: { title: 'Setting webdav', icon: 'link' }
      },
      {
        path: 'encrypt-local',
        name: 'encrypt-local',
        component: () => import('@/views/encrypt-local/index.vue'),
        meta: { title: 'encrypt local', icon: 'lock' }
      },
      {
        path: 'encrypt-online',
        name: 'encrypt-online',
        component: () => import('@/views/encrypt-online/index.vue'),
        meta: { title: 'encrypt online', icon: 'eye' }
      }
    ]
  },

  // ── 工具组 ──────────────────────────────
  {
    path: '/tools',
    component: Layout,
    redirect: '/tools/file-transfer',
    meta: { title: 'Tools', icon: 'operation' },
    children: [
      {
        path: 'file-transfer',
        name: 'file transfer',
        component: () => import('@/views/folder-convert/index.vue'),
        meta: { title: 'file transfer', icon: 'table' }
      }
    ]
  },
]

export const roleCodeRoutes = []
/**
 * asyncRoutes
 * the routes that need to be dynamically loaded based on user roles
 */
export const asyncRoutes = [
  // 404 page must be placed at the end !!!
  { path: '/:catchAll(.*)', name: 'CatchAll', redirect: '/404', hidden: true }
]

const router = createRouter({
  history: createWebHashHistory(),
  scrollBehavior: () => ({ top: 0 }),
  routes: constantRoutes
})

export default router