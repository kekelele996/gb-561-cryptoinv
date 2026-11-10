import { createRouter, createWebHistory } from 'vue-router'
import { setupGuards } from './guards'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/certs' },
    { path: '/login', name: 'login', component: () => import('../pages/LoginPage.vue'), meta: { public: true } },
    { path: '/certs', name: 'certs', component: () => import('../pages/CertsPage.vue'), meta: { title: '证书台账' } },
    {
      path: '/certs/:id',
      name: 'cert-detail',
      component: () => import('../pages/CertDetailPage.vue'),
      meta: { title: '证书详情' },
    },
    {
      path: '/endpoints',
      name: 'endpoints',
      component: () => import('../pages/EndpointsPage.vue'),
      meta: { title: 'TLS 端点' },
    },
    { path: '/matrix', name: 'matrix', component: () => import('../pages/MatrixPage.vue'), meta: { title: '算法风险矩阵' } },
    {
      path: '/migration',
      name: 'migration',
      component: () => import('../pages/MigrationPage.vue'),
      meta: { title: '迁移计划' },
    },
    { path: '/:pathMatch(.*)*', redirect: '/certs' },
  ],
})

setupGuards(router)

export default router
