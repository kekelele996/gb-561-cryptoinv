<template>
  <div class="gauge">
    <svg viewBox="0 0 120 68" role="img" :aria-label="`强度评分 ${display}`">
      <path d="M10 60 A50 50 0 0 1 110 60" fill="none" stroke="var(--ink-line)" stroke-width="7" />
      <path
        d="M10 60 A50 50 0 0 1 110 60"
        fill="none"
        :stroke="toneColor"
        stroke-width="7"
        :stroke-dasharray="`${arcLength} ${circumference}`"
        style="transition: stroke-dasharray 520ms var(--ease-expo)"
      />
      <circle cx="60" cy="60" r="2.5" fill="var(--copper)" />
    </svg>
    <div class="gauge-value">
      <strong class="mono" :style="{ color: toneColor }">{{ display }}</strong>
      <span class="caps">strength / 100</span>
    </div>
    <p v-if="caption" class="gauge-caption">{{ caption }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { scoreTone } from '../../utils/format'

const props = defineProps<{ score: number | null; caption?: string }>()

const circumference = Math.PI * 50
const display = computed(() => (props.score === null ? '—' : props.score.toFixed(1)))
const arcLength = computed(() => {
  const ratio = Math.max(0, Math.min(1, (props.score ?? 0) / 100))
  return (circumference * ratio).toFixed(1)
})
const toneColor = computed(() => {
  const tone = scoreTone(props.score)
  if (tone === 'ok') return 'var(--signal-ok)'
  if (tone === 'warn') return 'var(--signal-warn)'
  return 'var(--signal-bad)'
})
</script>

<style scoped>
.gauge { text-align: center; }
.gauge svg { width: 100%; max-width: 190px; }
.gauge-value strong { font-size: var(--step-3); display: block; line-height: 1.1; }
.gauge-value .caps { color: var(--muted); font-size: 10px; }
.gauge-caption { color: var(--muted); font-family: var(--font-mono); font-size: 10px; margin: 4px 0 0; }
</style>
