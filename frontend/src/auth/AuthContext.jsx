import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/endpoints.js'
import { setAdminToken } from '../api/client.js'
import { ApiError } from '../api/errors.js'

const STORAGE_KEY = 'cg.adminToken'
const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    try {
      return sessionStorage.getItem(STORAGE_KEY) || ''
    } catch {
      return ''
    }
  })
  const [status, setStatus] = useState(token ? 'checking' : 'anonymous')
  const [error, setError] = useState(null)
  const seq = useRef(0)
  const justLoggedIn = useRef(false)

  const clear = useCallback((message = null) => {
    try {
      sessionStorage.removeItem(STORAGE_KEY)
    } catch {
      // ignore
    }
    setAdminToken('')
    setToken('')
    setStatus('anonymous')
    setError(message)
  }, [])

  const validate = useCallback(async (value) => {
    const id = ++seq.current
    setStatus('checking')
    setError(null)
    try {
      await api.providers.list({ token: value })
      if (id !== seq.current) return false
      return true
    } catch (err) {
      if (id !== seq.current) return false
      if (err instanceof ApiError && err.isAuth) {
        clear('管理员令牌无效，请重新输入')
      } else {
        setStatus('error')
        setError(err)
      }
      return false
    }
  }, [clear])

  useEffect(() => {
    if (!token) {
      setStatus('anonymous')
      return
    }
    if (justLoggedIn.current) {
      // login() 已经验证过令牌；避免登录后立刻再发一次校验请求造成闪烁。
      justLoggedIn.current = false
      return
    }
    setAdminToken(token)
    let alive = true
    ;(async () => {
      const ok = await validate(token)
      if (!alive) return
      if (ok) setStatus('authenticated')
    })()
    return () => {
      alive = false
      seq.current += 1
    }
    // 只在 token 变化时校验；validate 本身是稳定的
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token])

  useEffect(() => {
    const onExpired = () => {
      if (token) clear('登录状态已失效，请重新输入管理员令牌')
    }
    window.addEventListener('cg:auth-expired', onExpired)
    return () => window.removeEventListener('cg:auth-expired', onExpired)
  }, [token, clear])

  const login = useCallback(async (raw) => {
    const value = (raw || '').trim()
    if (!value) throw new ApiError('请输入管理员令牌')
    await api.providers.list({ token: value })
    try {
      sessionStorage.setItem(STORAGE_KEY, value)
    } catch {
      // sessionStorage 不可用时仍允许本次会话使用内存令牌
    }
    justLoggedIn.current = true
    setAdminToken(value)
    setToken(value)
    setStatus('authenticated')
    setError(null)
  }, [])

  const retry = useCallback(async () => {
    if (!token) {
      setStatus('anonymous')
      return
    }
    setAdminToken(token)
    const ok = await validate(token)
    if (ok) setStatus('authenticated')
  }, [token, validate])

  const value = useMemo(() => ({
    token,
    status,
    error,
    login,
    logout: () => clear(null),
    retry,
  }), [token, status, error, login, retry, clear])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth 必须在 AuthProvider 内使用')
  return value
}
