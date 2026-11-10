<template>
  <div class="shell chart-grid">
    <aside class="rail">
      <span class="rail-name">云栖省政务云 · 密码资产盘点台</span>
      <svg class="rail-compass" viewBox="0 0 40 40" aria-hidden="true">
        <circle cx="20" cy="20" r="17" fill="none" stroke="currentColor" stroke-width="1" opacity="0.7" />
        <circle cx="20" cy="20" r="11" fill="none" stroke="currentColor" stroke-width="0.6" opacity="0.5" />
        <path d="M20 3 L23 20 L20 37 L17 20 Z" fill="currentColor" opacity="0.85" />
        <path d="M3 20 L20 17 L37 20 L20 23 Z" fill="currentColor" opacity="0.35" />
        <circle cx="20" cy="20" r="1.6" fill="var(--copper)" />
      </svg>
      <span class="mono" style="font-size: 10px; opacity: 0.55">N26°</span>
    </aside>

    <div class="main">
      <header class="topbar">
        <nav class="nav">
          <router-link to="/certs">证书台账</router-link>
          <router-link to="/endpoints">TLS 端点</router-link>
          <router-link to="/matrix">算法风险矩阵</router-link>
          <router-link to="/migration">迁移计划</router-link>
        </nav>
        <div class="row" style="gap: 14px">
          <span class="mono" style="font-size: var(--step--1); color: var(--muted)">
            {{ auth.user?.role_label || auth.role }}<template v-if="auth.dept"> · {{ auth.dept }}</template>
          </span>
          <span class="chip tag-soft">{{ auth.user?.display_name || auth.user?.email }}</span>
          <button class="btn ghost small" type="button" @click="signOut">退出</button>
        </div>
      </header>
      <main class="content">
        <slot />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAuthStore } from '../../stores/authStore'

const auth = useAuthStore()
const router = useRouter()

function signOut() {
  auth.logout()
  void router.push('/login')
}
</script>
