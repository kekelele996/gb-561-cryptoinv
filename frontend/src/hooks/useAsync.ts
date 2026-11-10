import { ref, type Ref } from 'vue'

export interface AsyncState<T> {
  data: Ref<T | null>
  loading: Ref<boolean>
  error: Ref<string>
  run: () => Promise<void>
}

export function useAsync<T>(loader: () => Promise<T>, immediate = true): AsyncState<T> {
  const data = ref<T | null>(null) as Ref<T | null>
  const loading = ref(false)
  const error = ref('')

  async function run(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      data.value = await loader()
    } catch (err) {
      error.value = (err as Error).message
    } finally {
      loading.value = false
    }
  }

  if (immediate) void run()
  return { data, loading, error, run }
}
