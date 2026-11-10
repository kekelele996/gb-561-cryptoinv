<template>
  <div class="pager">
    <span>共 {{ total }} 条 · 第 {{ page }} / {{ pages }} 页</span>
    <button class="btn ghost small" type="button" :disabled="page <= 1" @click="$emit('change', page - 1)">
      上一页
    </button>
    <button class="btn ghost small" type="button" :disabled="page >= pages" @click="$emit('change', page + 1)">
      下一页
    </button>
  </div>
</template>

<script setup lang="ts">
defineProps<{ page: number; pages: number; total: number }>()
defineEmits<{ (event: 'change', page: number): void }>()
</script>
