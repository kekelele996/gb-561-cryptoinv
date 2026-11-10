import http from './http'
import type { Paged } from '../types/cert'

export interface EndpointRow {
  id: string
  hostname: string
  port: number
  ip: string | null
  dept: string
  system_name: string
  dept_grade: string
  internet_facing: boolean
  tls_versions: string[]
  cipher_suites: string[]
  last_scanned_at: string | null
  risk_level: string
  simulated: boolean
  cert_count: number
  chain_validation: string | null
  chain_length: number
}

export interface EndpointSummary {
  total: number
  internet_facing: number
  scanned: number
  by_risk: Record<string, number>
}

export async function fetchEndpoints(params: {
  page?: number
  page_size?: number
  dept?: string
  internet_facing?: boolean
  risk_level?: string
  q?: string
}): Promise<Paged<EndpointRow> & { summary: EndpointSummary }> {
  const { data } = await http.get('/endpoints', { params })
  return data
}

export async function scanEndpoint(id: string): Promise<Record<string, unknown>> {
  const { data } = await http.post(`/endpoints/${id}/scan`)
  return data
}

export async function fetchEnums(): Promise<Record<string, string[]>> {
  const { data } = await http.get('/meta/enums')
  return data
}
