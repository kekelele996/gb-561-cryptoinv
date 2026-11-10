<template>
  <div class="row" style="gap: 5px">
    <span v-if="!tags.length" class="chip">无风险标签</span>
    <span
      v-for="tag in tags"
      :key="tag"
      class="chip"
      :class="hardTags.includes(tag as RiskTag) ? 'tag' : 'tag-soft'"
      :title="tag"
    >
      {{ RISK_TAG_LABEL[tag as RiskTag] ?? tag }}
    </span>
  </div>
</template>

<script setup lang="ts">
import { RiskTag } from '../../constants/enums'
import { RISK_TAG_LABEL } from '../../constants/labels'

defineProps<{ tags: string[] }>()

const hardTags: RiskTag[] = [
  RiskTag.WEAK_KEY,
  RiskTag.SHA1,
  RiskTag.EXPIRED,
  RiskTag.UNKNOWN_ALGO,
]
</script>
