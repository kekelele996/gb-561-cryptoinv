// 枚举中文标签与配色（只做展示映射，不含业务计算）
import type { ChainValidation, Compliance, ExpiryBucket, MigrationPriority, MigrationStatus, RiskTag } from './enums'

export const PRIORITY_LABEL: Record<MigrationPriority, string> = {
  P0: 'P0 · 立即处置',
  P1: 'P1 · 本季度',
  P2: 'P2 · 整改批次',
  P3: 'P3 · 规划窗口',
}

export const PRIORITY_ORDER: MigrationPriority[] = ['P0', 'P1', 'P2', 'P3']

export const WINDOW_LABEL: Record<string, string> = {
  '2026Q4': '2026 Q4 窗口',
  '2027Q1': '2027 Q1（国密改造窗口）',
  '2027Q2': '2027 Q2 窗口',
}

export const STATUS_LABEL: Record<MigrationStatus, string> = {
  todo: '待排期',
  scheduled: '已排期',
  in_progress: '迁移中',
  done: '已完成',
  blocked: '受阻',
}

export const VALIDATION_LABEL: Record<ChainValidation, string> = {
  is_valid: '链完整',
  expired: '已过期',
  name_mismatch: '域名不匹配',
  incomplete: '链不完整',
}

export const BUCKET_LABEL: Record<ExpiryBucket, string> = {
  expired: '已过期',
  soon_30: '30 天内到期',
  soon_90: '90 天内到期',
  normal: '正常',
}

export const COMPLIANCE_LABEL: Record<Compliance, string> = {
  compliant: '合规',
  non_compliant: '不合规',
  grace: '宽限期',
}

export const RISK_TAG_LABEL: Record<RiskTag, string> = {
  weak_key: '弱密钥',
  sha1: 'SHA-1 签名',
  expired: '已过期',
  self_signed: '自签',
  quantum_vulnerable: '量子脆弱',
  unknown_algo: '算法未识别',
}
