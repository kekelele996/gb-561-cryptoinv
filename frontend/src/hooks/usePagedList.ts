import { reactive, ref, watch, type Ref } from 'vue'
import type { Paged } from '../types/cert'

export interface PagedState<T> {
  rows: Ref<T[]>
  total: Ref<number>
  pages: Ref<number>
  loading: Ref<boolean>
  error: Ref<string>
  filters: Record<string, string | number | boolean | undefined>
  reload: () => Promise<void>
  page: Ref<number>
}

export function usePagedList<T>(
  fetcher: (params: Record<string, string | number | boolean | undefined>) => Promise<Paged<T> & Record<string, unknown>>,
  initial: Record<string, string | number | boolean | undefined> = {},
  pageSize = 20,
): PagedState<T> {
  const rows = ref([]) as Ref<T[]>
  const total = ref(0)
  const pages = ref(1)
  const page = ref(1)
  const loading = ref(false)
  const error = ref('')
  const filters = reactive({ ...initial })

  async function reload(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await fetcher({ ...filters, page: page.value, page_size: pageSize })
      rows.value = data.items as T[]
      total.value = data.total
      pages.value = data.pages
    } catch (err) {
      error.value = (err as Error).message
    } finally {
      loading.value = false
    }
  }

  watch(page, () => void reload())
  return { rows, total, pages, loading, error, filters, reload, page }
}
