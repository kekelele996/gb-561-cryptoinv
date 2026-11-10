<template>
  <div class="page-head">
    <div>
      <h1>{{ title }}</h1>
      <p v-if="sub" class="sub">{{ sub }}</p>
    </div>
    <div class="row"><slot /></div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ title: string; sub?: string }>()
</script>
