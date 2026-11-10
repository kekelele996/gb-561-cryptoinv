import { defineStore } from 'pinia'
import { fetchMe, login as apiLogin } from '../api/auth'
import { TOKEN_KEY } from '../utils/request'
import type { User } from '../types/user'
import type { UserRole } from '../constants/enums'

interface AuthState {
  token: string
  user: User | null
  loading: boolean
  error: string
}

export const useAuthStore = defineStore('auth', {
  state: (): AuthState => ({
    token: localStorage.getItem(TOKEN_KEY) ?? '',
    user: null,
    loading: false,
    error: '',
  }),
  getters: {
    isAuthenticated: (state): boolean => Boolean(state.token),
    role: (state): UserRole => (state.user?.role ?? 'owner') as UserRole,
    canWrite: (state): boolean => state.user?.role === 'admin' || state.user?.role === 'engineer',
    isAdmin: (state): boolean => state.user?.role === 'admin',
    isOwner: (state): boolean => state.user?.role === 'owner',
    displayName: (state): string => state.user?.display_name ?? '',
    dept: (state): string | null => state.user?.dept ?? null,
  },
  actions: {
    async login(email: string, password: string) {
      this.loading = true
      this.error = ''
      try {
        const result = await apiLogin(email, password)
        this.token = result.access_token
        this.user = result.user
        localStorage.setItem(TOKEN_KEY, result.access_token)
        return result
      } catch (error) {
        this.error = (error as Error).message
        throw error
      } finally {
        this.loading = false
      }
    },
    async restore() {
      if (!this.token) return
      try {
        const result = await fetchMe()
        this.user = result.user
      } catch {
        this.logout()
      }
    },
    logout() {
      this.token = ''
      this.user = null
      localStorage.removeItem(TOKEN_KEY)
    },
  },
})
