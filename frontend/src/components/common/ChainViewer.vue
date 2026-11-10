<template>
  <div v-if="chain" class="chain">
    <div class="chain-head">
      <span class="mono">链长 {{ chain.chain_length }}</span>
      <span class="chip" :class="chain.validation === 'is_valid' ? 'valid' : 'invalid'">
        {{ VALIDATION_LABEL[chain.validation] }}
      </span>
      <span class="mono" style="font-size: 10px; color: var(--muted)">{{ chain.validated_at }}</span>
    </div>
    <div class="chain-row">
      <template v-for="(link, index) in chain.links" :key="link.cert_id">
        <div class="chain-node" :class="{ ca: link.is_ca, missing: link.missing }" :style="{ animationDelay: `${index * 120}ms` }">
          <span class="chain-role mono">{{ link.missing ? '缺证书' : link.is_ca ? 'CA' : '叶' }}</span>
          <strong>{{ link.subject_cn || link.cert_id }}</strong>
          <span class="mono chain-meta">
            {{ link.sig_algo || '—' }}<template v-if="link.key_bits"> · {{ link.key_bits }}b</template>
          </span>
          <span class="mono chain-meta">issuer: {{ link.issuer_cn || '—' }}</span>
          <span class="mono chain-meta">到期 {{ formatDate(link.not_after) }}</span>
        </div>
        <span v-if="index < chain.links.length - 1" class="chain-arrow" aria-hidden="true">签发 →</span>
      </template>
    </div>
    <p class="chain-detail">{{ chain.error_detail }}</p>
  </div>
  <EmptyState v-else title="该证书未关联链校验记录" hint="只有挂了端点的生效叶证书才参与端点级链校验。" />
</template>

<script setup lang="ts">
import EmptyState from './EmptyState.vue'
import type { ChainDetail } from '../../types/cert'
import { VALIDATION_LABEL } from '../../constants/labels'
import { formatDate } from '../../utils/format'

defineProps<{ chain: ChainDetail | null }>()
</script>

<style scoped>
.chain-head { display: flex; gap: 10px; align-items: center; margin-bottom: var(--space-3); flex-wrap: wrap; }
.chain-row { display: flex; align-items: stretch; flex-wrap: wrap; gap: 6px; }
.chain-node {
  border: 1px solid var(--ink-line); padding: 8px 10px; min-width: 168px;
  display: flex; flex-direction: column; gap: 2px;
  background: color-mix(in oklch, var(--ink-panel) 62%, transparent);
}
.chain-node.ca { border-color: color-mix(in oklch, var(--copper) 55%, transparent); }
.chain-node.missing { border-style: dashed; border-color: var(--seal-red); opacity: 0.75; }
.chain-node strong { font-family: var(--font-display); font-size: var(--step-0); color: var(--paper); }
.chain-role { color: var(--copper-bright); font-size: 10px; letter-spacing: 0.16em; }
.chain-meta { font-size: 10px; color: var(--muted); white-space: nowrap; }
.chain-arrow { align-self: center; color: var(--copper); font-family: var(--font-mono); font-size: 11px; }
.chain-detail { font-family: var(--font-mono); font-size: 11px; color: var(--muted); margin: var(--space-3) 0 0; }
</style>
