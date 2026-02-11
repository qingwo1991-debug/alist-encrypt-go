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
  {
    path: '/',
    component: Layout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/index.vue'),
        meta: { title: 'Dashboard', elSvgIcon: 'Fold', affix: true }
      }
    ]
  },
  {
    path: '/setting-alist',
    component: Layout,
    children: [
      {
        path: 'index',
        component: () => import('@/views/setting-alist/index.vue'),
        name: 'alist',
        meta: { title: 'Setting alist', icon: 'example' }
      }
    ]
  },
  {
    path: '/setting-webdav',
    component: Layout,
    children: [
      {
        path: 'index',
        component: () => import('@/views/setting-webdav/index.vue'),
        name: 'webdav',
        meta: { title: 'Setting webdav', icon: 'example' }
      }
    ]
  },
  {
    path: '/encrypt-local',
    component: Layout,
    children: [
      {
        path: 'index',
        component: () => import('@/views/encrypt-local/index.vue'),
        name: 'encrypt-local',
        meta: { title: 'encrypt local', icon: 'example' }
      }
    ]
  },
  {
    path: '/encrypt-online',
    component: Layout,
    children: [
      {
        path: 'index',
        component: () => import('@/views/encrypt-online/index.vue'),
        name: 'encrypt-online',
        meta: { title: 'encrypt online', icon: 'example' }
      }
    ]
  },
  {
    path: '/file-transfer',
    component: Layout,
    children: [
      {
        path: 'index',
        component: () => import('@/views/folder-convert/index.vue'),
        name: 'file transfer',
        meta: { title: 'file transfer', icon: 'example' }
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
