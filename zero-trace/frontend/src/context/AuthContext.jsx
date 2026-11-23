import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import api from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(Boolean(api.getToken()))

  const refresh = useCallback(async () => {
    if (!api.getToken()) {
      setUser(null)
      setLoading(false)
      return null
    }
    try {
      const { data } = await api.get('/auth/me/')
      setUser(data)
      return data
    } catch {
      api.setToken(null)
      setUser(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const handleUnauthorized = () => {
      setUser(null)
    }
    window.addEventListener('zerotrace:unauthorized', handleUnauthorized)
    return () => window.removeEventListener('zerotrace:unauthorized', handleUnauthorized)
  }, [refresh])

  const login = async (email, password) => {
    const { data } = await api.post('/auth/login/', { email, password })
    api.setToken(data.token)
    setUser(data.user)
    return data.user
  }

  const register = async (username, email, password) => {
    const { data } = await api.post('/auth/register/', { username, email, password })
    api.setToken(data.token)
    setUser(data.user)
    return data.user
  }

  const logout = async () => {
    try {
      await api.post('/auth/logout/')
    } catch {
      api.setToken(null)
    }
    api.setToken(null)
    setUser(null)
  }

  const setConsent = async (aiConsent) => {
    const { data } = await api.post('/auth/consent/', { ai_consent: aiConsent })
    setUser(data)
    return data
  }

  const value = useMemo(
    () => ({ user, loading, login, register, logout, refresh, setConsent }),
    [user, loading, refresh],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
