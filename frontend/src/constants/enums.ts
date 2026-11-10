// 共享枚举：与后端 backend/src/constants/enums.py 字面量严格一致（README 列出现位置）
export const MigrationPriority = {
  P0: 'P0',
  P1: 'P1',
  P2: 'P2',
  P3: 'P3',
} as const
export type MigrationPriority = (typeof MigrationPriority)[keyof typeof MigrationPriority]

export const ChainValidation = {
  IS_VALID: 'is_valid',
  EXPIRED: 'expired',
  NAME_MISMATCH: 'name_mismatch',
  INCOMPLETE: 'incomplete',
} as const
export type ChainValidation = (typeof ChainValidation)[keyof typeof ChainValidation]

export const RiskTag = {
  WEAK_KEY: 'weak_key',
  SHA1: 'sha1',
  EXPIRED: 'expired',
  SELF_SIGNED: 'self_signed',
  QUANTUM_VULNERABLE: 'quantum_vulnerable',
  UNKNOWN_ALGO: 'unknown_algo',
} as const
export type RiskTag = (typeof RiskTag)[keyof typeof RiskTag]

export const Compliance = {
  COMPLIANT: 'compliant',
  NON_COMPLIANT: 'non_compliant',
  GRACE: 'grace',
} as const
export type Compliance = (typeof Compliance)[keyof typeof Compliance]

export const ExpiryBucket = {
  EXPIRED: 'expired',
  SOON_30: 'soon_30',
  SOON_90: 'soon_90',
  NORMAL: 'normal',
} as const
export type ExpiryBucket = (typeof ExpiryBucket)[keyof typeof ExpiryBucket]

export const MigrationStatus = {
  TODO: 'todo',
  SCHEDULED: 'scheduled',
  IN_PROGRESS: 'in_progress',
  DONE: 'done',
  BLOCKED: 'blocked',
} as const
export type MigrationStatus = (typeof MigrationStatus)[keyof typeof MigrationStatus]

export const UserRole = {
  ADMIN: 'admin',
  ENGINEER: 'engineer',
  OWNER: 'owner',
} as const
export type UserRole = (typeof UserRole)[keyof typeof UserRole]
