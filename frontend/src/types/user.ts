import type { UserRole } from '../constants/enums'

export interface User {
  id: string
  email: string
  display_name: string
  role: UserRole
  dept: string | null
  is_active: boolean
  role_label?: string
  permissions?: string[]
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: User
}
