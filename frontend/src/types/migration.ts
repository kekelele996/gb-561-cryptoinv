import type { MigrationPriority, MigrationStatus } from '../constants/enums'

export interface MigrationRow {
  id: string
  certificate_id: string
  subject_cn: string
  serial: string
  algo_label: string
  sig_algo: string
  key_bits: number | null
  hostname: string
  dept: string
  system_name: string
  internet_facing: boolean
  dept_grade: string
  target_algo: string
  priority: MigrationPriority
  priority_score: number
  batch_window: string
  status: MigrationStatus
  rationale: string
  strength_score: number
  risk_tags: string[]
  days_left: number | null
  not_after: string
  planned_at: string | null
  done_at: string | null
  allowed_transitions: MigrationStatus[]
}

export interface MigrationSummary {
  total: number
  by_priority: Record<string, number>
  by_status: Record<string, number>
  by_window: Record<string, number>
}

export interface MatrixCell {
  algo: string
  dept: string
  count: number
  avg_score: number | null
  non_compliant: number
  weak: number
  expired: number
}

export interface MatrixData {
  algos: string[]
  depts: string[]
  cells: MatrixCell[]
  dept_stats: {
    dept: string
    count: number
    avg_score: number
    non_compliant: number
    weak: number
    expired: number
  }[]
  algo_stats: { algo: string; count: number; avg_score: number; non_compliant: number; weak: number }[]
  metric: string
  total_certificates: number
}

export interface MigrationGenerateResult {
  created: number
  refreshed: number
  total: number
  computed_by_priority: Record<string, number>
  manual_review: { certificate_id: string; subject_cn: string }[]
  generated_at: string
}
