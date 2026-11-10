import { defineStore } from 'pinia'
import { fetchCertDetail, fetchCertSummary } from '../api/certs'
import type { CertDetail, CertSummary } from '../types/cert'

interface CertState {
  summary: CertSummary | null
  detail: CertDetail | null
  loading: boolean
  error: string
  lastAssessment: Record<string, unknown> | null
}

export const useCertStore = defineStore('cert', {
  state: (): CertState => ({
    summary: null,
    detail: null,
    loading: false,
    error: '',
    lastAssessment: null,
  }),
  getters: {
    expiredCount: (state): number => state.summary?.buckets.expired ?? 0,
    soon30Count: (state): number => state.summary?.buckets.soon_30 ?? 0,
    soon90Count: (state): number => state.summary?.buckets.soon_90 ?? 0,
    normalCount: (state): number => state.summary?.buckets.normal ?? 0,
  },
  actions: {
    async loadSummary() {
      try {
        this.summary = await fetchCertSummary()
      } catch (error) {
        this.error = (error as Error).message
      }
    },
    async loadDetail(id: string) {
      this.loading = true
      this.error = ''
      try {
        this.detail = await fetchCertDetail(id)
      } catch (error) {
        this.error = (error as Error).message
        this.detail = null
      } finally {
        this.loading = false
      }
    },
    setLastAssessment(payload: Record<string, unknown> | null) {
      this.lastAssessment = payload
    },
  },
})
