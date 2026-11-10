import http from './http'
import type { CertDetail, CertRow, CertSummary, Paged } from '../types/cert'
import type { MatrixData } from '../types/migration'

export interface CertQuery {
  page?: number
  page_size?: number
  bucket?: string
  algo?: string
  risk_tag?: string
  dept?: string
  q?: string
}

export async function fetchCerts(params: CertQuery): Promise<Paged<CertRow>> {
  const { data } = await http.get('/certificates', { params })
  return data
}

export async function fetchCertSummary(): Promise<CertSummary> {
  const { data } = await http.get('/certificates/summary')
  return data
}

export async function fetchCertDetail(id: string): Promise<CertDetail> {
  const { data } = await http.get(`/certificates/${id}`)
  return data
}

export async function fetchMatrix(metric = 'avg_score'): Promise<MatrixData> {
  const { data } = await http.get('/matrix', { params: { metric } })
  return data
}

export async function runAssessment(): Promise<{
  run_id: string
  mode: string
  status: string
  summary?: Record<string, unknown>
}> {
  const { data } = await http.post('/assessments/run', { mode: 'auto' })
  return data
}

export async function fetchAssessmentRun(runId: string): Promise<{
  run_id: string
  phase: string
  detail: Record<string, unknown>
}> {
  const { data } = await http.get(`/assessments/runs/${runId}`)
  return data
}

export async function fetchAssessmentSummary(): Promise<{
  buckets: Record<string, number>
  compliance: Record<string, number>
  risk_tags: Record<string, number>
  avg_score: number
  cert_total: number
}> {
  const { data } = await http.get('/assessments/summary')
  return data
}
