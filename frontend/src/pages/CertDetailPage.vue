<template>
  <div class="fade-in">
    <PageHead :title="detail?.certificate.subject_cn || '证书详情'" sub="解析字段由后端 cryptography 真解析 PEM 得到；页脚哈希为 DER 的 sha256。">
      <button class="btn ghost" type="button" @click="router.back()">返回台账</button>
    </PageHead>

    <p v-if="store.error" class="error">{{ store.error }}</p>

    <template v-if="detail">
      <section class="grid-3" style="margin-bottom: var(--space-4)">
        <div class="panel">
          <h2 class="panel-title">强度评分</h2>
          <ScoreGauge :score="detail.assessment?.strength_score ?? null" :caption="detail.assessment ? `合规结论：${COMPLIANCE_LABEL[detail.assessment.compliance]}` : '尚未评估'" />
          <div class="weights mono">
            <span>key {{ detail.assessment?.key_strength ?? '—' }}</span>
            <span>sig {{ detail.assessment?.sig_strength ?? '—' }}</span>
            <span>validity {{ detail.assessment?.validity_strength ?? '—' }}</span>
            <span>chain {{ detail.assessment?.chain_trust ?? '—' }}</span>
            <span>agility {{ detail.assessment?.agility ?? '—' }}</span>
          </div>
        </div>
        <div class="panel">
          <h2 class="panel-title">风险标签</h2>
          <RiskTagChip :tags="detail.assessment?.risk_tags ?? []" />
          <dl class="kv" style="margin-top: var(--space-3)">
            <dt>时效档</dt><dd class="mono">{{ detail.certificate.expiry_bucket }} · {{ formatDays(detail.certificate.days_left) }}</dd>
            <dt>合规</dt><dd class="mono">{{ detail.assessment ? COMPLIANCE_LABEL[detail.assessment.compliance] : '未评估' }}</dd>
            <dt>来源</dt><dd class="mono">{{ detail.certificate.source === 'scan' ? '模拟扫描' : 'PEM 导入' }}</dd>
            <dt>生效中</dt><dd class="mono">{{ detail.certificate.is_active ? '是（当前叶证书）' : '否（历史证书）' }}</dd>
            <dt>库支持</dt><dd class="mono">{{ detail.certificate.unsupported_by_crypto_lib ? '否（仅 OID 级识别）' : '是' }}</dd>
          </dl>
        </div>
        <div class="panel">
          <h2 class="panel-title">有效期</h2>
          <ExpiryBar :bucket="detail.certificate.expiry_bucket" :days-left="detail.certificate.days_left" />
          <dl class="kv" style="margin-top: var(--space-3)">
            <dt>not_before</dt><dd class="mono">{{ formatDate(detail.certificate.not_before) }}</dd>
            <dt>not_after</dt><dd class="mono">{{ formatDate(detail.certificate.not_after) }}</dd>
            <dt>序列号</dt><dd class="mono">{{ detail.certificate.serial }}</dd>
            <dt>签名算法</dt><dd class="mono">{{ detail.certificate.sig_algo }}（{{ detail.certificate.sig_algo_oid }}）</dd>
            <dt>公钥</dt><dd class="mono">{{ detail.certificate.pubkey_algo }} {{ detail.certificate.key_bits ?? '—' }}b</dd>
          </dl>
        </div>
      </section>

      <section class="panel" style="margin-bottom: var(--space-4)">
        <h2 class="panel-title">链视图（issuer == subject + AKI/SKI 构建）</h2>
        <ChainViewer :chain="detail.chain" />
      </section>

      <section class="grid-2">
        <div class="panel">
          <h2 class="panel-title">解析字段</h2>
          <dl class="kv wide">
            <dt>subject_dn</dt><dd class="mono">{{ detail.certificate.subject_dn }}</dd>
            <dt>issuer_dn</dt><dd class="mono">{{ detail.certificate.issuer_dn }}</dd>
            <dt>SAN</dt><dd class="mono">{{ detail.certificate.san.join(', ') || '（无 SAN 扩展）' }}</dd>
            <dt>SKI</dt><dd class="mono">{{ detail.certificate.ski || '—' }}</dd>
            <dt>AKI</dt><dd class="mono">{{ detail.certificate.aki || '—' }}</dd>
            <dt>DER sha256</dt><dd class="mono break">{{ detail.certificate.sha256 }}</dd>
            <dt>端点</dt>
            <dd class="mono">
              {{ detail.endpoint ? `${detail.endpoint.hostname}:${detail.endpoint.port} · ${detail.endpoint.dept} · ${detail.endpoint.dept_grade} 级` : '（CA 材料 / 未挂端点）' }}
            </dd>
          </dl>
        </div>
        <div class="panel">
          <h2 class="panel-title">迁移项</h2>
          <template v-if="detail.migration">
            <dl class="kv wide">
              <dt>优先级</dt><dd class="mono">{{ detail.migration.priority }} · score {{ detail.migration.priority_score }}</dd>
              <dt>批次窗口</dt><dd class="mono">{{ WINDOW_LABEL[detail.migration.batch_window] || detail.migration.batch_window }}</dd>
              <dt>目标算法</dt><dd class="mono">{{ detail.migration.target_algo }}</dd>
              <dt>状态</dt><dd class="mono">{{ STATUS_LABEL[detail.migration.status as never] || detail.migration.status }}</dd>
              <dt>口径</dt><dd class="mono" style="font-size: 10px">{{ detail.migration.rationale }}</dd>
            </dl>
            <button class="btn ghost small" style="margin-top: var(--space-3)" type="button" @click="router.push('/migration')">
              去迁移计划推进
            </button>
          </template>
          <EmptyState v-else title="该证书不在迁移清单" hint="迁移清单只收录 P0-P3 中已生成的条目；可在迁移页点「生成 / 刷新清单」。" />
        </div>
      </section>
    </template>
    <EmptyState v-else-if="!store.loading" title="证书不存在" hint="链接可能已失效，返回台账重选。" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '../components/common/PageHead.vue'
import ExpiryBar from '../components/common/ExpiryBar.vue'
import RiskTagChip from '../components/common/RiskTagChip.vue'
import ChainViewer from '../components/common/ChainViewer.vue'
import ScoreGauge from '../components/common/ScoreGauge.vue'
import EmptyState from '../components/common/EmptyState.vue'
import { useCertStore } from '../stores/certStore'
import { COMPLIANCE_LABEL, STATUS_LABEL, WINDOW_LABEL } from '../constants/labels'
import { formatDate, formatDays } from '../utils/format'

const route = useRoute()
const router = useRouter()
const store = useCertStore()
const detail = computed(() => store.detail)

async function load(id: string) {
  await store.loadDetail(id)
}

onMounted(() => load(String(route.params.id)))
watch(() => route.params.id, (id) => { if (id) void load(String(id)) })
</script>

<style scoped>
.kv { display: grid; grid-template-columns: 96px 1fr; gap: 6px 10px; margin: 0; }
.kv.wide { grid-template-columns: 104px 1fr; }
.kv dt { font-family: var(--font-mono); font-size: 10px; color: var(--muted); letter-spacing: 0.06em; }
.kv dd { margin: 0; font-size: 11px; color: var(--paper-dim); }
.break { word-break: break-all; }
.weights { display: flex; flex-wrap: wrap; gap: 8px; margin-top: var(--space-3); font-size: 10px; color: var(--muted); }
</style>
