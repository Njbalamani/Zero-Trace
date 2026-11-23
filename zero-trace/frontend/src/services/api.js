import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || '/api'
const TOKEN_KEY = 'zerotrace_token'

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
})

api.getToken = () => localStorage.getItem(TOKEN_KEY)

api.setToken = (token) => {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

api.interceptors.request.use((config) => {
  const token = api.getToken()
  if (token) config.headers.Authorization = `Token ${token}`
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !error.config?.url?.includes('/auth/login/')) {
      api.setToken(null)
      window.dispatchEvent(new CustomEvent('zerotrace:unauthorized'))
    }
    return Promise.reject(error)
  },
)

api.downloadReport = async (scanId) => {
  const response = await api.get(`/scans/${scanId}/report/`, { responseType: 'blob' })
  const url = window.URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `zerotrace-report-${scanId}.pdf`
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)
}

export const errorMessage = (error, fallback = 'Something went wrong.') =>
  error?.response?.data?.detail ||
  Object.values(error?.response?.data || {})[0]?.[0] ||
  error?.message ||
  fallback

export default api
