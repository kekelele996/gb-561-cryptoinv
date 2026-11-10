<template>
  <div class="fade-in">
    <PageHead title="证书台账" sub="到期看板四档计数由 not_after 与当前时间实时计算；分数与标签来自全量评估批次。">
      <button class="btn" type="button" :disabled="running" @click="runFullAssessment">
        {{ running ? `评估中（${runPhase}）` : '跑全量评估' }}
      </button>
    </PageHead>

    <section class="metrics" style="margin-bottom: var(--space-4)">
      <div class="metric bad">
        <span class="label">已过期</span>
        <span class="value">{{ certStore.expiredCount }}</span>
      </div>
      <div class="metric warn">
        <span class="label">30 天内到期</span>
        <span class="value">{{ certStore.soon30Count }}</span>
      </div>
      <div class="metric">
        <span class="label">90 天内到期</span>
        <span class="value">{{ certStore.soon90Count }}</span>
      </div>
      <div class="metric ok">
        <span class="label">正常 / 平均分</span>
        <span class="value">{{ certStore.normalCount }} <small class="mono" style="font-size: 12px; color: var(--muted)">avg {{ certStore.summary?.avg_score ?? '—' }}</small></span>
      </div>
    </section>

    <div class="toolbar">
      <div class="field">
        <label>时效档</label>
        <select v-model="bucket" @change="reload">
          <option value="">全部</option>
          <option value="expired">已过期</option>
          <option value="soon_30">30 天内</option>
          <option value="soon_90">90 天内</option>
          <option value="normal">正常</option>
        </select>
      </div>
      <div class="field">
        <label>算法分桶</label>
        <select v-model="algo" @change="reload">
          <option value="">全部</option>
          <option v-for="item in algoOptions" :key="item" :value="item">{{ item }}</option>
        </select>
      </div>
      <div class="field">
        <label>风险标签</label>
        <select v-model="riskTag" @change="reload">
          <option value="">全部</option>
          <option v-for="item in tagOptions" :key="item" :value="item">{{ RISK_TAG_LABEL[item] }}</option>
        </select>
      </div>
      <div class="field" style="min-width: 220px">
        <label>检索（CN / 序列号 / 主机名）</label>
        <input v-model="keyword" placeholder="例如 rj / legacy / 5610" @keyup.enter="reload" />
      </div>
      <button class="btn ghost" type="button" @click="resetFilters">重置</button>
    </div>

    <p v-if="loadError" class="error">{{ loadError }}</p>
    <p v-if="lastAssessment" class="notice" style="margin-bottom: var(--space-3)">
      评估批次 {{ lastAssessment.run_id }}（{{ lastAssessment.mode }}）已完成：证书
      {{ lastAssessment.cert_total }} 张，合规 {{ lastAssessment.compliant }} / 宽限
      {{ lastAssessment.grace }} / 不合规 {{ lastAssessment.non_compliant }}，平均分 {{ lastAssessment.avg_score }}。
    </p>

    <div class="panel">
      <table class="data">
        <thead>
          <tr>
            <th>主体 CN / 主机名</th>
            <th>厅局</th>
            <th>算法</th>
            <th>有效期</th>
            <th>强度</th>
            <th>风险标签</th>
            <th>链</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id" class="clickable" @click="openDetail(row.id)">
            <td>
              <div class="truncate" style="color: var(--paper)">{{ row.subject_cn }}</div>
              <div class="mono truncate" style="font-size: 10px; color: var(--muted)">
                {{ row.hostname || '（CA / 未挂端点）' }}
              </div>
            </td>
            <td class="mono" style="font-size: 11px">{{ row.dept || '—' }}</td>
            <td>
              <div class="mono" style="font-size: 11px">{{ row.algo_label }}</div>
              <div class="mono" style="font-size: 10px; color: var(--muted)">{{ row.sig_algo }}</div>
            </td>
            <td><ExpiryBar :bucket="row.expiry_bucket" :days-left="row.days_left" :not-after="row.not_after" /></td>
            <td class="num" style="min-width: 62px">
              <span :style="{ color: scoreColor(row.strength_score) }">{{ formatScore(row.strength_score) }}</span>
            </td>
            <td><RiskTagChip :tags="row.risk_tags" /></td>
            <td class="mono" style="font-size: 10px">
              <span :class="row.chain_validation === 'is_valid' ? 'ok' : 'bad'">{{ row.chain_validation || '未建链' }}</span>
            </td>
          </tr>
          <tr v-if="!rows.length && !loading">
            <td colspan="7">
              <EmptyState title="没有匹配的证书" hint="试试清空筛选条件，或先跑一次全量评估。" />
            </td>
          </tr>
        </tbody>
      </table>
      <Pagination :page="page" :pages="pages" :total="total" @change="changePage" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '../components/common/PageHead.vue'
import ExpiryBar from '../components/common/ExpiryBar.vue'
import RiskTagChip from '../components/common/RiskTagChip.vue'
import Pagination from '../components/common/Pagination.vue'
import EmptyState from '../components/common/EmptyState.vue'
import { fetchAssessmentRun, fetchCerts, runAssessment } from '../api/certs'
import { useCertStore } from '../stores/certStore'
import type { CertRow } from '../types/cert'
import { RiskTag } from '../constants/enums'
import { RISK_TAG_LABEL } from '../constants/labels'
import { formatScore } from '../utils/format'

const router = useRouter()
const route = useRoute()
const certStore = useCertStore()

const rows = ref<CertRow[]>([])
const total = ref(0)
const pages = ref(1)
const page = ref(1)
const loading = ref(false)
const loadError = ref('')
const bucket = ref('')
const algo = ref('')
const riskTag = ref('')
const keyword = ref('')
const running = ref(false)
const runPhase = ref('queued')
const lastAssessment = ref<Record<string, unknown> | null>(null)

const algoOptions = ['RSA-2048+', 'RSA-SHA1', 'RSA-1024', 'ECDSA-P256', 'ECDSA-P384', 'SM2-SM3', 'UNKNOWN']
const tagOptions = Object.values(RiskTag)

function scoreColor(score: number | null): string {
  if (score === null) return 'var(--muted)'
  if (score >= 80) return 'var(--signal-ok)'
  if (score >= 60) return 'var(--signal-warn)'
  return 'var(--signal-bad)'
}

async function reload() {
  loading.value = true
  loadError.value = ''
  try {
    const data = await fetchCerts({
      page: page.value,
      page_size: 20,
      bucket: bucket.value || undefined,
      algo: algo.value || undefined,
      risk_tag: riskTag.value || undefined,
      q: keyword.value || undefined,
    })
    rows.value = data.items
    total.value = data.total
    pages.value = data.pages
  } catch (err) {
    loadError.value = (err as Error).message
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  bucket.value = ''
  algo.value = ''
  riskTag.value = ''
  keyword.value = ''
  page.value = 1
  void reload()
}

function changePage(next: number) {
  page.value = next
  void reload()
}

function openDetail(id: string) {
  void router.push(`/certs/${id}`)
}

async function runFullAssessment() {
  running.value = true
  runPhase.value = 'queued'
  try {
    const started = await runAssessment()
    let detail: Record<string, unknown> = (started.summary as Record<string, unknown>) ?? {}
    if (started.status !== 'done') {
      for (let attempt = 0; attempt < 40; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 800))
        const progress = await fetchAssessmentRun(started.run_id)
        runPhase.value = progress.phase
        if (progress.phase === 'done' || progress.phase === 'failed') {
          detail = progress.detail
          break
        }
      }
    }
    lastAssessment.value = { run_id: started.run_id, mode: started.mode, ...detail }
    certStore.setLastAssessment(lastAssessment.value)
    await certStore.loadSummary()
    await reload()
  } catch (err) {
    loadError.value = (err as Error).message
  } finally {
    running.value = false
  }
}

function readQueryFilters() {
  // 支持深链：/certs?algo=RSA-SHA1&bucket=expired&q=legacy
  bucket.value = typeof route.query.bucket === 'string' ? route.query.bucket : ''
  algo.value = typeof route.query.algo === 'string' ? route.query.algo : ''
  riskTag.value = typeof route.query.risk_tag === 'string' ? route.query.risk_tag : ''
  keyword.value = typeof route.query.q === 'string' ? route.query.q : ''
}

onMounted(async () => {
  readQueryFilters()
  await certStore.loadSummary()
  await reload()
})
</script>

<style scoped>
.chip.ok, span.ok { color: var(--signal-ok); }
span.bad { color: var(--signal-bad); }
</style>
