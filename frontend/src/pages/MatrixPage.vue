<template>
  <div class="fade-in">
    <PageHead title="算法风险矩阵" sub="行=算法分桶，列=厅局；格值由全量评估结果聚合（平均强度分 / 不合规数 / 弱算法数）。">
      <button class="btn ghost" type="button" @click="reload" :disabled="loading">刷新</button>
    </PageHead>

    <div class="toolbar">
      <div class="field">
        <label>热力口径</label>
        <select v-model="metric">
          <option value="avg_score">平均强度分</option>
          <option value="non_compliant">不合规数</option>
          <option value="weak">弱算法数</option>
        </select>
      </div>
      <span class="mono" style="font-size: 11px; color: var(--muted)">证书总量 {{ data?.total_certificates ?? 0 }}</span>
    </div>

    <div class="grid-2">
      <div class="panel" style="overflow-x: auto">
        <h2 class="panel-title">算法 × 厅局</h2>
        <table class="data heat">
          <thead>
            <tr>
              <th>算法 \ 厅局</th>
              <th v-for="dept in data?.depts ?? []" :key="dept" class="vertical">{{ dept.replace('省', '') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="algo in data?.algos ?? []" :key="algo">
              <th class="mono rowhead">{{ algo }}</th>
              <td
                v-for="dept in data?.depts ?? []"
                :key="algo + dept"
                class="cell"
                :style="{ background: cellBackground(findCell(algo, dept)) }"
                :title="cellTitle(findCell(algo, dept))"
              >
                <span class="mono">{{ cellText(findCell(algo, dept)) }}</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="mono legend">深色=更差；空格表示该厅局无该算法证书。</p>
      </div>

      <div class="stack">
        <div class="panel">
          <h2 class="panel-title">厅局平均分（升序，最低者先整改）</h2>
          <table class="data">
            <thead><tr><th>厅局</th><th class="num">证书</th><th class="num">平均分</th><th class="num">不合规</th><th class="num">弱算法</th></tr></thead>
            <tbody>
              <tr v-for="row in data?.dept_stats ?? []" :key="row.dept">
                <td>{{ row.dept }}</td>
                <td class="num">{{ row.count }}</td>
                <td class="num" :style="{ color: scoreColor(row.avg_score) }">{{ formatScore(row.avg_score) }}</td>
                <td class="num">{{ row.non_compliant }}</td>
                <td class="num">{{ row.weak }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel">
          <h2 class="panel-title">算法分布</h2>
          <table class="data">
            <thead><tr><th>算法分桶</th><th class="num">证书</th><th class="num">平均分</th><th class="num">不合规</th><th class="num">弱算法</th></tr></thead>
            <tbody>
              <tr v-for="row in data?.algo_stats ?? []" :key="row.algo">
                <td class="mono">{{ row.algo }}</td>
                <td class="num">{{ row.count }}</td>
                <td class="num" :style="{ color: scoreColor(row.avg_score) }">{{ formatScore(row.avg_score) }}</td>
                <td class="num">{{ row.non_compliant }}</td>
                <td class="num">{{ row.weak }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import PageHead from '../components/common/PageHead.vue'
import { useAsync } from '../hooks/useAsync'
import { fetchMatrix } from '../api/certs'
import type { MatrixCell, MatrixData } from '../types/migration'
import { formatScore } from '../utils/format'

const metric = ref('avg_score')
const { data, loading, run: loadMatrix } = useAsync<MatrixData>(() => fetchMatrix(metric.value), false)

function scoreColor(score: number | null): string {
  if (score === null) return 'var(--muted)'
  if (score >= 80) return 'var(--signal-ok)'
  if (score >= 60) return 'var(--signal-warn)'
  return 'var(--signal-bad)'
}

function findCell(algo: string, dept: string): MatrixCell | undefined {
  return data.value?.cells.find((item) => item.algo === algo && item.dept === dept)
}

function cellText(cell?: MatrixCell): string {
  if (!cell || !cell.count) return ''
  if (metric.value === 'non_compliant') return String(cell.non_compliant)
  if (metric.value === 'weak') return String(cell.weak)
  return cell.avg_score === null ? '—' : cell.avg_score.toFixed(0)
}

function cellBackground(cell?: MatrixCell): string {
  if (!cell || !cell.count) return 'transparent'
  let ratio = 0
  if (metric.value === 'non_compliant') ratio = Math.min(1, cell.non_compliant / 4)
  else if (metric.value === 'weak') ratio = Math.min(1, cell.weak / 3)
  else ratio = Math.max(0, Math.min(1, (100 - (cell.avg_score ?? 100)) / 60))
  const alpha = 0.1 + ratio * 0.55
  return `color-mix(in oklch, var(--seal-red) ${Math.round(alpha * 100)}%, transparent)`
}

function cellTitle(cell?: MatrixCell): string {
  if (!cell || !cell.count) return '该厅局无此算法证书'
  return `${cell.algo} @ ${cell.dept}：${cell.count} 张，平均分 ${cell.avg_score ?? '—'}，不合规 ${cell.non_compliant}，弱算法 ${cell.weak}，过期 ${cell.expired}`
}

function reload() {
  void loadMatrix()
}

watch(metric, reload)
onMounted(reload)
</script>

<style scoped>
th.vertical { writing-mode: vertical-rl; text-orientation: mixed; height: 96px; font-size: 10px; letter-spacing: 0.06em; }
.rowhead { text-align: left; font-weight: 400; color: var(--paper-dim); font-size: 11px; border-bottom: 1px solid color-mix(in oklch, var(--ink-line) 45%, transparent); }
.cell { text-align: center; font-size: 11px; color: var(--paper); min-width: 46px; }
.legend { font-size: 10px; color: var(--muted); margin-top: var(--space-3); }
</style>
