import http from './http'
import type { Paged } from '../types/cert'
import type { MigrationGenerateResult, MigrationRow, MigrationSummary } from '../types/migration'

export async function fetchMigrationItems(params: {
  page?: number
  page_size?: number
  priority?: string
  status?: string
  window?: string
  dept?: string
}): Promise<Paged<MigrationRow> & { summary: MigrationSummary }> {
  const { data } = await http.get('/migration', { params })
  return data
}

export async function generateMigration(): Promise<MigrationGenerateResult> {
  const { data } = await http.post('/migration/generate', {})
  return data
}

export async function transitionItem(id: string, toStatus: string): Promise<Record<string, unknown>> {
  const { data } = await http.post(`/migration/${id}/transition`, { to_status: toStatus })
  return data
}

export function migrationCsvUrl(priority?: string): string {
  const query = priority ? `?priority=${encodeURIComponent(priority)}` : ''
  return `/api/migration/export.csv${query}`
}

export async function downloadMigrationCsv(priority?: string): Promise<{ rows: number; text: string }> {
  const { data } = await http.get(migrationCsvUrl(priority).replace('/api', ''), { responseType: 'text' })
  const text = String(data)
  return { rows: Math.max(0, text.trim().split('\n').length - 1), text }
}
