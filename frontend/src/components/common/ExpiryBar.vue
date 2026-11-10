<template>
  <div class="expiry">
    <div class="expiry-track">
      <div class="expiry-fill" :class="bucket" :style="{ width: `${widthPct}%` }" />
    </div>
    <span class="expiry-label mono" :class="bucket">{{ labelText }}</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { ExpiryBucket } from '../../constants/enums'
import { formatDays } from '../../utils/format'
import { BUCKET_LABEL } from '../../constants/labels'

const props = defineProps<{
  bucket: ExpiryBucket
  daysLeft: number | null
  notAfter?: string
  /** 可选：有效期总长（天），用于画进度占比 */
  spanDays?: number
}>()

const widthPct = computed(() => {
  if (props.bucket === 'expired') return 100
  const days = props.daysLeft ?? 0
  const span = props.spanDays ?? 800
  const remaining = Math.max(0, Math.min(1, days / span))
  return Math.round((1 - remaining) * 100)
})

const labelText = computed(() => {
  const head = BUCKET_LABEL[props.bucket] ?? props.bucket
  return `${head} · ${formatDays(props.daysLeft)}`
})
</script>

<style scoped>
.expiry { display: flex; align-items: center; gap: 8px; min-width: 190px; }
.expiry-track { flex: 1; height: 5px; background: color-mix(in oklch, var(--ink-line) 55%, transparent); position: relative; }
.expiry-fill { height: 100%; transition: width 420ms var(--ease-expo); }
.expiry-fill.expired { background: var(--seal-red); }
.expiry-fill.soon_30 { background: var(--signal-warn); }
.expiry-fill.soon_90 { background: var(--copper-bright); }
.expiry-fill.normal { background: var(--signal-ok); }
.expiry-label { font-size: 10px; white-space: nowrap; }
.expiry-label.expired { color: var(--signal-bad); }
.expiry-label.soon_30 { color: var(--signal-warn); }
.expiry-label.normal { color: var(--signal-ok); }
</style>
