import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * 读取一份管理面数据；可选短轮询。
 * - 失败时保留旧数据（便于页面展示「数据可能过期」而不是整页空白）
 * - 页面隐藏时暂停轮询，重新可见时立即刷新
 * - 同一时刻最多一个请求在途，避免慢请求叠加
 */
export function useResource(loader, deps = [], { pollMs = 0, enabled = true } = {}) {
  const loaderRef = useRef(loader)
  loaderRef.current = loader
  const [state, setState] = useState({
    data: null,
    error: null,
    loading: enabled,
    lastUpdated: null,
  })
  const seq = useRef(0)
  const alive = useRef(true)
  const inFlight = useRef(false)

  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
      seq.current += 1
    }
  }, [])

  const run = useCallback(async ({ quiet = false } = {}) => {
    // 轮询不叠加；筛选条件变化 / 手动刷新则允许发起新请求，由 seq 丢弃旧结果。
    if (quiet && inFlight.current) return
    inFlight.current = true
    const id = ++seq.current
    if (!quiet) {
      setState((prev) => ({ ...prev, loading: prev.data == null }))
    }
    try {
      const data = await loaderRef.current()
      if (!alive.current || id !== seq.current) return
      setState({ data, error: null, loading: false, lastUpdated: Date.now() })
    } catch (error) {
      if (error?.name === 'AbortError') return
      if (!alive.current || id !== seq.current) return
      setState((prev) => ({ ...prev, error, loading: false }))
    } finally {
      inFlight.current = false
    }
  }, [])

  useEffect(() => {
    if (!enabled) {
      setState((prev) => ({ ...prev, loading: false }))
      return undefined
    }
    let cancelled = false
    let timer = null

    const tick = (quiet) => {
      if (cancelled) return
      if (typeof document !== 'undefined' && document.hidden) return
      run({ quiet })
    }

    tick(false)
    if (pollMs > 0) {
      timer = setInterval(() => tick(true), pollMs)
      const onVisibility = () => {
        if (typeof document !== 'undefined' && !document.hidden) tick(true)
      }
      document.addEventListener('visibilitychange', onVisibility)
      return () => {
        cancelled = true
        clearInterval(timer)
        document.removeEventListener('visibilitychange', onVisibility)
      }
    }
    return () => {
      cancelled = true
    }
    // loader 通过 ref 保持最新；deps 由调用方声明查询条件
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, enabled])

  return {
    ...state,
    reload: run,
  }
}
