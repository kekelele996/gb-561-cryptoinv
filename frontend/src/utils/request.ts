import axios, { type AxiosInstance, type AxiosError } from 'axios'

export const TOKEN_KEY = 'cryptoinv.token'

export interface ApiError {
  code: string
  message: string
  detail: string
  trace_id?: string
}

export function createHttp(baseURL: string): AxiosInstance {
  const http = axios.create({ baseURL, timeout: 30000 })
  http.interceptors.request.use((config) => {
    const token = localStorage.getItem(TOKEN_KEY)
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
  })
  http.interceptors.response.use(
    (response) => response,
    (error: AxiosError<ApiError>) => {
      const payload = error.response?.data
      if (payload && typeof payload === 'object' && 'message' in payload) {
        return Promise.reject(new Error(payload.message || payload.detail || '请求失败'))
      }
      return Promise.reject(new Error(error.message || '网络异常'))
    },
  )
  return http
}
