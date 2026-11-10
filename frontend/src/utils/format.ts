// 展示层格式化（纯显示，不做业务计算）
export function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return value.toFixed(2)
}

export function formatDays(days: number | null | undefined): string {
  if (days === null || days === undefined) return '—'
  if (days < 0) return `已过期 ${Math.abs(days)} 天`
  return `剩余 ${days} 天`
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const dt = new Date(iso)
  if (Number.isNaN(dt.getTime())) return iso
  return dt.toISOString().slice(0, 10)
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const dt = new Date(iso)
  if (Number.isNaN(dt.getTime())) return iso
  return dt.toISOString().slice(0, 16).replace('T', ' ')
}

export function shortHash(value: string | null | undefined, size = 16): string {
  if (!value) return '—'
  return `${value.slice(0, size)}…`
}

export function scoreTone(score: number | null | undefined): 'ok' | 'warn' | 'bad' {
  if (score === null || score === undefined) return 'warn'
  if (score >= 80) return 'ok'
  if (score >= 60) return 'warn'
  return 'bad'
}

export function countText(map: Record<string, number>, key: string): number {
  return map?.[key] ?? 0
}
