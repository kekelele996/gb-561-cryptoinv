import type { ChainValidation, Compliance, ExpiryBucket, RiskTag } from '../constants/enums'

export interface CertRow {
  id: string
  cert_key: string
  subject_cn: string
  issuer_cn: string
  serial: string
  pubkey_algo: string
  key_bits: number | null
  sig_algo: string
  algo_label: string
  not_before: string
  not_after: string
  days_left: number | null
  expiry_bucket: ExpiryBucket
  expiry_label: string
  is_ca: boolean
  is_active: boolean
  source: string
  sha256: string
  unsupported_by_crypto_lib: boolean
  dept: string | null
  system_name: string | null
  hostname: string | null
  internet_facing: boolean | null
  endpoint_id: string | null
  chain_validation: ChainValidation | null
  strength_score: number | null
  compliance: Compliance | null
  risk_tags: RiskTag[]
}

export interface ChainLink {
  cert_id: string
  subject_cn?: string
  issuer_cn?: string
  is_ca?: boolean
  sig_algo?: string
  key_bits?: number | null
  pubkey_algo?: string
  not_before?: string
  not_after?: string
  missing?: boolean
}

export interface ChainDetail {
  chain_length: number
  validation: ChainValidation
  validated_at: string
  error_detail: string
  links: ChainLink[]
}

export interface Assessment {
  strength_score: number
  risk_tags: RiskTag[]
  compliance: Compliance
  key_strength: number
  sig_strength: number
  validity_strength: number
  chain_trust: number
  agility: number
  expiry_bucket: ExpiryBucket
  days_left: number | null
  assessed_at: string
}

export interface EndpointDetail {
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
}

export interface CertDetail {
  certificate: {
    id: string
    cert_key: string
    subject_cn: string
    issuer_cn: string
    subject_dn: string
    issuer_dn: string
    san: string[]
    serial: string
    not_before: string
    not_after: string
    days_left: number | null
    expiry_bucket: ExpiryBucket
    pubkey_algo: string
    key_bits: number | null
    sig_algo: string
    sig_algo_oid: string
    is_ca: boolean
    is_active: boolean
    ski: string | null
    aki: string | null
    sha256: string
    source: string
    unsupported_by_crypto_lib: boolean
    algo_label: string
  }
  endpoint: EndpointDetail | null
  assessment: Assessment | null
  chain: ChainDetail | null
  migration: {
    id: string
    target_algo: string
    priority: string
    priority_score: number
    batch_window: string
    status: string
    rationale: string
  } | null
}

export interface CertSummary {
  cert_total: number
  buckets: Record<ExpiryBucket, number>
  bucket_labels: Record<string, string>
  by_algo: Record<string, number>
  by_compliance: Record<string, number>
  avg_score: number
  assessed: number
}

export interface Paged<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  pages: number
}
