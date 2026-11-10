<template>
  <div class="login chart-grid">
    <section class="login-map" aria-hidden="true">
      <svg viewBox="0 0 420 420" class="login-compass">
        <circle cx="210" cy="210" r="186" fill="none" stroke="var(--ink-line)" stroke-width="0.8" />
        <circle cx="210" cy="210" r="140" fill="none" stroke="var(--ink-line)" stroke-width="0.5" />
        <circle cx="210" cy="210" r="92" fill="none" stroke="var(--ink-line)" stroke-width="0.5" />
        <path d="M210 30 L222 210 L210 390 L198 210 Z" fill="var(--copper)" opacity="0.55" />
        <path d="M30 210 L210 198 L390 210 L210 222 Z" fill="var(--sea-green)" opacity="0.35" />
        <text x="210" y="16" text-anchor="middle" fill="var(--copper)" font-family="Space Mono" font-size="11">N</text>
        <text x="210" y="408" text-anchor="middle" fill="var(--muted)" font-family="Space Mono" font-size="11">S</text>
        <text x="402" y="214" fill="var(--muted)" font-family="Space Mono" font-size="11">E</text>
        <text x="8" y="214" fill="var(--muted)" font-family="Space Mono" font-size="11">W</text>
      </svg>
      <ol class="login-steps">
        <li><span class="mono">01</span> 登记厅局 TLS 端点，导入证书 PEM</li>
        <li><span class="mono">02</span> X.509 真解析 · 链校验 · 时效分级</li>
        <li><span class="mono">03</span> 强度评分 · 风险标签 · 密评举证</li>
        <li><span class="mono">04</span> 国密迁移清单与批次窗口</li>
      </ol>
    </section>

    <section class="login-panel panel-paper">
      <p class="caps" style="color: color-mix(in oklch, var(--paper-ink) 60%, var(--copper))">云栖省政务云 · 密码应用中心</p>
      <h1>密码学资产盘点<br />与迁移清单台</h1>
      <p class="login-sub">
        等保 2.0 密评举证 · 国密改造窗口 2027Q1 · 12 厅局 / 40 端点 / 52 张证书
      </p>

      <form class="login-form" @submit.prevent="submit">
        <div class="field on-paper">
          <label for="email">邮箱（演示账号）</label>
          <input id="email" v-model="email" type="email" autocomplete="username" placeholder="engineer@cryptoinv.demo" />
        </div>
        <div class="field on-paper">
          <label for="password">口令</label>
          <input id="password" v-model="password" type="password" autocomplete="current-password" placeholder="Demo@2026" />
        </div>
        <p v-if="error" class="error">{{ error }}</p>
        <button class="btn" type="submit" :disabled="auth.loading">
          {{ auth.loading ? '正在核验证书管理员身份…' : '进入盘点台' }}
        </button>
      </form>

      <div class="login-accounts">
        <p class="caps">演示账号（口令统一 Demo@2026）</p>
        <button type="button" class="account" @click="fill('engineer@cryptoinv.demo')">
          <span class="mono">engineer</span> 录入 / 扫描 / 评估 / 生成迁移项
        </button>
        <button type="button" class="account" @click="fill('admin@cryptoinv.demo')">
          <span class="mono">admin</span> 全部读写 + 导出审批
        </button>
        <button type="button" class="account" @click="fill('owner@cryptoinv.demo')">
          <span class="mono">owner</span> 本厅局只读 + 确认迁移窗口
        </button>
      </div>
      <p class="login-note">
        本系统不连接真实 CA / TLS 端点；全部证书为合成样本，扫描为受控模拟。
      </p>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/authStore'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const email = ref('engineer@cryptoinv.demo')
const password = ref('Demo@2026')
const error = ref('')

function fill(value: string) {
  email.value = value
}

async function submit() {
  error.value = ''
  try {
    await auth.login(email.value.trim(), password.value)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/certs'
    await router.push(redirect)
  } catch (err) {
    error.value = (err as Error).message
  }
}
</script>

<style scoped>
.login { display: grid; grid-template-columns: 1.15fr 0.85fr; min-height: 100vh; align-items: center; gap: var(--space-6); padding: var(--space-6) var(--space-7); }
.login-map { display: flex; flex-direction: column; gap: var(--space-5); }
.login-compass { width: 100%; max-width: 420px; }
.login-steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; max-width: 420px; }
.login-steps li { font-family: var(--font-mono); font-size: var(--step--1); color: var(--paper-dim); border-left: 1px solid var(--ink-line); padding-left: 10px; }
.login-steps .mono { color: var(--copper-bright); margin-right: 8px; }
.login-panel { padding: var(--space-6); max-width: 520px; }
.login-panel h1 { font-size: var(--step-4); line-height: 1.04; margin: var(--space-2) 0; color: var(--paper-ink); }
.login-sub { font-family: var(--font-mono); font-size: var(--step--1); color: color-mix(in oklch, var(--paper-ink) 70%, transparent); margin: 0 0 var(--space-5); }
.login-form { display: grid; gap: var(--space-3); }
.field.on-paper label { color: color-mix(in oklch, var(--paper-ink) 66%, transparent); }
.field.on-paper input { background: color-mix(in oklch, var(--paper) 92%, white); border: 1px solid color-mix(in oklch, var(--paper-ink) 30%, transparent); color: var(--paper-ink); }
.on-paper.btn, .login-form .btn { justify-self: start; }
.login-accounts { margin-top: var(--space-5); border-top: 1px dashed color-mix(in oklch, var(--paper-ink) 28%, transparent); padding-top: var(--space-3); display: grid; gap: 6px; }
.login-accounts .caps { color: color-mix(in oklch, var(--paper-ink) 60%, transparent); margin: 0 0 4px; }
.account { text-align: left; background: transparent; border: 1px solid color-mix(in oklch, var(--paper-ink) 22%, transparent); color: var(--paper-ink); padding: 6px 9px; font-family: var(--font-mono); font-size: 11px; }
.account .mono { color: color-mix(in oklch, var(--paper-ink) 75%, var(--copper)); margin-right: 6px; }
.login-note { margin-top: var(--space-4); font-family: var(--font-mono); font-size: 10px; color: color-mix(in oklch, var(--paper-ink) 58%, transparent); }
@media (max-width: 1023px) { .login { grid-template-columns: 1fr; padding: var(--space-4); } .login-map { display: none; } }
</style>
