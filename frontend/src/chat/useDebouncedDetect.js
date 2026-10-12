import { useEffect, useState } from 'react'
import { api } from '../api.js'

// 300ms debounce 敏感检测(spec §4.1 发送前实时高亮;复用现有 /api/detect)
export default function useDebouncedDetect(text) {
  const [entities, setEntities] = useState([])
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!text || !text.trim()) {
      setEntities([])
      setPending(false)
      return undefined
    }
    setPending(true)
    let cancelled = false
    const timer = setTimeout(async () => {
      try {
        const r = await api.detect(text)
        if (!cancelled) setEntities(r?.entities || [])
      } catch {
        if (!cancelled) setEntities([])
      } finally {
        if (!cancelled) setPending(false)
      }
    }, 300)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [text])

  return { entities, pending }
}
