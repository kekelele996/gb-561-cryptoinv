import { defineStore } from 'pinia'
import { fetchMigrationItems, generateMigration, transitionItem } from '../api/migration'
import type { MigrationGenerateResult, MigrationRow, MigrationSummary } from '../types/migration'

interface MigrationState {
  rows: MigrationRow[]
  summary: MigrationSummary | null
  total: number
  pages: number
  page: number
  loading: boolean
  error: string
  filters: { priority?: string; status?: string; window?: string }
  lastGenerate: MigrationGenerateResult | null
}

export const useMigrationStore = defineStore('migration', {
  state: (): MigrationState => ({
    rows: [],
    summary: null,
    total: 0,
    pages: 1,
    page: 1,
    loading: false,
    error: '',
    filters: {},
    lastGenerate: null,
  }),
  actions: {
    async load() {
      this.loading = true
      this.error = ''
      try {
        const data = await fetchMigrationItems({
          page: this.page,
          page_size: 20,
          ...this.filters,
        })
        this.rows = data.items
        this.summary = data.summary
        this.total = data.total
        this.pages = data.pages
      } catch (error) {
        this.error = (error as Error).message
      } finally {
        this.loading = false
      }
    },
    async generate(): Promise<MigrationGenerateResult> {
      const result = await generateMigration()
      this.lastGenerate = result
      await this.load()
      return result
    },
    async transition(id: string, toStatus: string) {
      await transitionItem(id, toStatus)
      await this.load()
    },
    setPage(page: number) {
      this.page = page
    },
    setFilter(key: 'priority' | 'status' | 'window', value: string | undefined) {
      this.filters = { ...this.filters, [key]: value || undefined }
      this.page = 1
    },
  },
})
