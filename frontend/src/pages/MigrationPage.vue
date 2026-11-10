<template>
  <div class="fade-in">
    <PageHead title="迁移计划" sub="P0-P3 与批次窗口由 strength_score / urgency / dept_grade / internet_facing 真实推导；owner 可确认本厅局窗口。">
      <button class="btn ghost" type="button" @click="reload" :disabled="store.loading">刷新</button>
      <button v-if="auth.canWrite" class="btn" type="button" :disabled="generating" @click="generate">
        {{ generating ? '生成中…' : '生成 / 刷新清单' }}
      </button>
      <button v-if="auth.canWrite || auth.isAdmin" class="btn" type="button" :disabled="exporting" @click="exportCsv">
        {{ exporting ? '导出中…' : '导出 CSV' }}
      </button>
    </PageHead>

    <section class="metrics" style="margin-bottom: var(--space-4)">
      <div class="metric bad"><span class="label">P0 立即处置</span><span class="value">{{ store.summary?.by_priority.P0 ?? 0 }}</span></div>
      <div class="metric warn"><span class="label">P1 本季度</span><span class="value">{{ store.summary?.by_priority.P1 ?? 0 }}</span></div>
      <div class="metric"><span class="label">P2 整改批次</span><span class="value">{{ store.summary?.by_priority.P2 ?? 0 }}</span></div>
      <div class="metric ok"><span class="label">P3 规划窗口</span><span class="value">{{ store.summary?.by_priority.P3 ?? 0 }}</span></div>
    </section>

    <p v-if="generateResult" class="notice" style="margin-bottom: var(--space-3)">
      清单生成完成：新增 {{ generateResult.created }} 条，刷新 {{ generateResult.refreshed }} 条，总计
      {{ generateResult.total }} 条；按算法重算 P0={{ generateResult.computed_by_priority?.P0 ?? 0 }}
      P1={{ generateResult.computed_by_priority?.P1 ?? 0 }} · 人工清单 {{ generateResult.manual_review?.length ?? 0 }} 张（算法未识别）。
    </p>
    <p v-if="exportInfo" class="notice" style="margin-bottom: var(--space-3)">
      CSV 已导出：{{ exportInfo.filename }}，数据行 {{ exportInfo.rows }} 行（已触发浏览器下载并在审计日志留痕）。
    </p>
    <p v-if="actionError" class="error">{{ actionError }}</p>

    <div class="toolbar">
      <div class="field">
        <label>优先级</label>
        <select :value="store.filters.priority ?? ''" @change="onFilter('priority', ($event.target as HTMLSelectElement).value)">
          <option value="">全部</option>
          <option v-for="item in PRIORITY_ORDER" :key="item" :value="item">{{ PRIORITY_LABEL[item] }}</option>
        </select>
      </div>
      <div class="field">
        <label>状态</label>
        <select :value="store.filters.status ?? ''" @change="onFilter('status', ($event.target as HTMLSelectElement).value)">
          <option value="">全部</option>
          <option v-for="(label, value) in STATUS_LABEL" :key="value" :value="value">{{ label }}</option>
        </select>
      </div>
      <div class="field">
        <label>批次窗口</label>
        <select :value="store.filters.window ?? ''" @change="onFilter('window', ($event.target as HTMLSelectElement).value)">
          <option value="">全部</option>
          <option v-for="(label, value) in WINDOW_LABEL" :key="value" :value="value">{{ label }}</option>
        </select>
      </div>
      <span class="mono" style="font-size: 11px; color: var(--muted)">
        窗口分布：<template v-for="(count, window) in store.summary?.by_window ?? {}" :key="window">{{ window }} {{ count }} · </template>
      </span>
    </div>

    <div class="panel">
      <table class="data">
        <thead>
          <tr>
            <th>优先级 / 分数</th><th>证书 / 端点</th><th>厅局</th><th>目标算法</th>
            <th>批次窗口</th><th>状态</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in store.rows" :key="row.id">
            <td>
              <span class="chip" :class="row.priority === 'P0' ? 'tag' : 'tag-soft'">{{ row.priority }}</span>
              <div class="mono" style="font-size: 10px; color: var(--muted)">score {{ row.priority_score }}</div>
            </td>
            <td>
              <div class="truncate" style="color: var(--paper)">{{ row.subject_cn }}</div>
              <div class="mono truncate" style="font-size: 10px; color: var(--muted)">
                {{ row.hostname }} · {{ row.algo_label }} · {{ formatDays(row.days_left) }}
              </div>
            </td>
            <td class="mono" style="font-size: 11px">{{ row.dept }}<span style="color: var(--muted)"> · {{ row.dept_grade }}</span></td>
            <td class="mono" style="font-size: 11px">{{ row.target_algo }}</td>
            <td class="mono" style="font-size: 10px">{{ WINDOW_LABEL[row.batch_window] || row.batch_window }}</td>
            <td><span class="chip">{{ STATUS_LABEL[row.status] }}</span></td>
            <td>
              <div class="row" style="gap: 4px">
                <button
                  v-for="next in allowedActions(row)"
                  :key="next"
                  class="btn small"
                  type="button"
                  :disabled="transitioningId === row.id"
                  @click="transition(row.id, next)"
                >
                  → {{ STATUS_LABEL[next] }}
                </button>
              </div>
            </td>
          </tr>
          <tr v-if="!store.rows.length && !store.loading">
            <td colspan="7"><EmptyState title="迁移清单为空" hint="点击右上「生成 / 刷新清单」，系统会按评估结果补建 P0/P1 条目。" /></td>
          </tr>
        </tbody>
      </table>
      <Pagination :page="store.page" :pages="store.pages" :total="store.total" @change="changePage" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PageHead from '../components/common/PageHead.vue'
import Pagination from '../components/common/Pagination.vue'
import EmptyState from '../components/common/EmptyState.vue'
import { downloadMigrationCsv } from '../api/migration'
import { useAuthStore } from '../stores/authStore'
import { useMigrationStore } from '../stores/migrationStore'
import type { MigrationGenerateResult, MigrationRow } from '../types/migration'
import type { MigrationStatus } from '../constants/enums'
import { PRIORITY_LABEL, PRIORITY_ORDER, STATUS_LABEL, WINDOW_LABEL } from '../constants/labels'
import { formatDays } from '../utils/format'

const auth = useAuthStore()
const store = useMigrationStore()
const generating = ref(false)
const exporting = ref(false)
const transitioningId = ref('')
const actionError = ref('')
const generateResult = ref<MigrationGenerateResult | null>(null)
const exportInfo = ref<{ filename: string; rows: number } | null>(null)

function allowedActions(row: MigrationRow): MigrationStatus[] {
  if (auth.isOwner) {
    // owner 只能确认窗口（todo -> scheduled）或标注受阻
    return row.allowed_transitions.filter((item) => item === 'scheduled' || item === 'blocked')
  }
  return row.allowed_transitions
}

async function reload() {
  await store.load()
}

function changePage(next: number) {
  store.setPage(next)
  void store.load()
}

function onFilter(key: 'priority' | 'status' | 'window', value: string) {
  store.setFilter(key, value || undefined)
  void store.load()
}

async function generate() {
  generating.value = true
  actionError.value = ''
  try {
    generateResult.value = await store.generate()
  } catch (err) {
    actionError.value = (err as Error).message
  } finally {
    generating.value = false
  }
}

async function transition(id: string, next: string) {
  transitioningId.value = id
  actionError.value = ''
  try {
    await store.transition(id, next)
  } catch (err) {
    actionError.value = (err as Error).message
  } finally {
    transitioningId.value = ''
  }
}

async function exportCsv() {
  exporting.value = true
  actionError.value = ''
  try {
    const result = await downloadMigrationCsv()
    const blob = new Blob([result.text], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'cryptoinv-migration-list.csv'
    link.click()
    URL.revokeObjectURL(url)
    exportInfo.value = { filename: 'cryptoinv-migration-list.csv', rows: result.rows }
  } catch (err) {
    actionError.value = (err as Error).message
  } finally {
    exporting.value = false
  }
}

onMounted(reload)
</script>
