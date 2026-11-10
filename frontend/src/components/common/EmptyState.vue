<template>
  <div class="empty">
    <strong>{{ title }}</strong>
    <span class="hint">{{ hint }}</span>
    <slot />
  </div>
</template>

<script setup lang="ts">
defineProps<{ title: string; hint?: string }>()
</script>
