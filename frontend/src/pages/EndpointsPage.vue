<template>
  <div class="fade-in">
    <PageHead title="TLS 端点" sub="40 个厅局对外端点；18 个已登记证书并建链，22 个待扫描。">
      <button class="btn" type="button" @click="reload" :disabled="loading">刷新</button>
    </PageHead>

    <p class="notice warn" style="margin-bottom: var(--space-4)">
      模拟扫描声明：本系统<b>不发起真实 TLS 握手</b>。扫描按 hostname 的 sha256 确定性挑选本地 fixture PEM，
      再用 cryptography 真解析证书、真建链、真评分并落库；页面标注「模拟」的结果不得作为线上实测证据。
    </p>

    <section class="metrics" style="margin-bottom: var(--space-4)">
      <div class="metric"><span class="label">端点总数</span><span class="value">{{ summary?.total ?? 0 }}</span></div>
      <div class="metric"><span class="label">互联网暴露</span><span class="value">{{ summary?.internet_facing ?? 0 }}</span></div>
      <div class="metric ok"><span class="label">已扫描</span><span class="value">{{ summary?.scanned ?? 0 }}</span></div>
      <div class="metric bad"><span class="label">高危 / 严重</span><span class="value">{{ highRisk }}</span></div>
    </section>

    <div class="grid-2">
      <div class="panel">
        <table class="data">
          <thead>
            <tr><th>主机名</th><th>厅局 / 系统</th><th>暴露</th><th>TLS</th><th>风险</th><th>证书</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="row in rows" :key="row.id" :class="{ selected: row.id === selected?.id }">
              <td>
                <div class="mono">{{ row.hostname }}<span style="color: var(--muted)">:{{ row.port }}</span></div>
                <div class="mono" style="font-size: 10px; color: var(--muted)">{{ row.ip }}</div>
              </td>
              <td>
                <div style="color: var(--paper)">{{ row.dept }}</div>
                <div class="mono truncate" style="font-size: 10px; color: var(--muted)">{{ row.system_name }} · {{ row.dept_grade }} 级</div>
              </td>
              <td class="mono" style="font-size: 11px">{{ row.internet_facing ? '公网' : '内网' }}</td>
              <td class="mono" style="font-size: 10px">{{ row.tls_versions.join(' / ') || '未扫描' }}</td>
              <td><span class="chip" :class="riskClass(row.risk_level)">{{ row.risk_level }}</span></td>
              <td class="mono" style="font-size: 11px">
                {{ row.cert_count }} 张<template v-if="row.chain_validation"> · {{ row.chain_validation }}</template>
              </td>
              <td>
                <button class="btn small" type="button" :disabled="scanningId === row.id" @click="scan(row)">
                  {{ scanningId === row.id ? '扫描中…' : '模拟扫描' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <Pagination :page="page" :pages="pages" :total="total" @change="changePage" />
      </div>

      <div class="panel">
        <h2 class="panel-title">扫描结果</h2>
        <template v-if="scanResult">
          <p class="notice" style="margin-bottom: var(--space-3)">
            模拟扫描 · fixture {{ scanMeta?.cert_fixture }} · 风险 {{ scanMeta?.risk_level }}
          </p>
          <dl class="kv">
            <dt>端点</dt><dd class="mono">{{ scanEndpointInfo?.hostname }}:{{ scanEndpointInfo?.port }}</dd>
            <dt>TLS 版本</dt><dd class="mono">{{ (scanMeta?.tls_versions as string[])?.join(' / ') }}</dd>
            <dt>密码套件</dt><dd class="mono">{{ (scanMeta?.cipher_suites as string[])?.join(' / ') }}</dd>
            <dt>证书主体</dt><dd class="mono">{{ scanCert?.subject_cn }}</dd>
            <dt>公钥 / 签名</dt><dd class="mono">{{ scanCert?.pubkey_algo }} {{ scanCert?.key_bits }}b · {{ scanCert?.sig_algo }}</dd>
            <dt>链校验</dt><dd class="mono">{{ scanChain?.validation }}（链长 {{ scanChain?.chain_length }}）</dd>
            <dt>备注</dt><dd class="mono">{{ (scanMeta?.notes as string[])?.join('；') }}</dd>
          </dl>
          <template v-if="scanAssessment">
            <p class="caps" style="margin-top: var(--space-3)">本次重算（全量）</p>
            <p class="mono" style="font-size: 11px; color: var(--muted)">
              证书 {{ scanAssessment.cert_total }} · 链 {{ scanAssessment.chain_total }} ·
              合规 {{ scanAssessment.compliant }} / 不合规 {{ scanAssessment.non_compliant }} · avg {{ scanAssessment.avg_score }}
            </p>
          </template>
        </template>
        <EmptyState v-else title="还没有扫描结果" hint="在左侧点「模拟扫描」，会用本地 fixture PEM 真解析一张证书并重算链与评分。" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PageHead from '../components/common/PageHead.vue'
import Pagination from '../components/common/Pagination.vue'
import EmptyState from '../components/common/EmptyState.vue'
import { fetchEndpoints, scanEndpoint, type EndpointRow, type EndpointSummary } from '../api/endpoints'

const rows = ref<EndpointRow[]>([])
const summary = ref<EndpointSummary | null>(null)
const total = ref(0)
const pages = ref(1)
const page = ref(1)
const loading = ref(false)
const scanningId = ref('')
const selected = ref<EndpointRow | null>(null)
const scanResult = ref<Record<string, unknown> | null>(null)

const highRisk = computed(() => (summary.value?.by_risk.high ?? 0) + (summary.value?.by_risk.critical ?? 0))
const scanMeta = computed(() => (scanResult.value?.scan as Record<string, unknown>) ?? null)
const scanEndpointInfo = computed(() => (scanResult.value?.endpoint as Record<string, unknown>) ?? null)
const scanCert = computed(() => (scanResult.value?.certificate as Record<string, unknown>) ?? null)
const scanChain = computed(() => (scanResult.value?.chain as Record<string, unknown>) ?? null)
const scanAssessment = computed(() => (scanResult.value?.assessment_summary as Record<string, unknown>) ?? null)

function riskClass(level: string): string {
  if (level === 'critical' || level === 'high') return 'invalid'
  if (level === 'low') return 'valid'
  return ''
}

async function reload() {
  loading.value = true
  try {
    const data = await fetchEndpoints({ page: page.value, page_size: 20 })
    rows.value = data.items
    total.value = data.total
    pages.value = data.pages
    summary.value = data.summary
  } finally {
    loading.value = false
  }
}

function changePage(next: number) {
  page.value = next
  void reload()
}

async function scan(row: EndpointRow) {
  scanningId.value = row.id
  selected.value = row
  try {
    scanResult.value = await scanEndpoint(row.id)
    await reload()
  } finally {
    scanningId.value = ''
  }
}

onMounted(reload)
</script>

<style scoped>
tr.selected { background: color-mix(in oklch, var(--copper) 9%, transparent); }
.kv { display: grid; grid-template-columns: 92px 1fr; gap: 6px 10px; margin: 0; }
.kv dt { font-family: var(--font-mono); font-size: 10px; color: var(--muted); letter-spacing: 0.08em; }
.kv dd { margin: 0; font-size: 11px; color: var(--paper-dim); }
</style>
