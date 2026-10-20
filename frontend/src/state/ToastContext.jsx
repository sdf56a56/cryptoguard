import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'

const ToastContext = createContext(null)

const TONES = {
  info: 'border-line bg-surface text-ink',
  ok: 'border-ok/30 bg-ok-soft text-ok',
  warn: 'border-warn/30 bg-warn-soft text-warn',
  bad: 'border-bad/30 bg-bad-soft text-bad',
}

export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const seq = useRef(0)

  const remove = useCallback((id) => {
    setItems((prev) => prev.filter((item) => item.id !== id))
  }, [])

  const push = useCallback((message, tone = 'info') => {
    const id = ++seq.current
    setItems((prev) => [...prev.slice(-3), { id, message: String(message || ''), tone }])
    setTimeout(() => remove(id), 4500)
    return id
  }, [remove])

  const value = useMemo(() => ({ push, remove }), [push, remove])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-[100] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2"
        aria-live="polite"
        aria-atomic="false"
      >
        {items.map((item) => (
          <div
            key={item.id}
            role="status"
            className={`cg-fade-in flex items-start gap-3 rounded-lg border px-3.5 py-3 text-sm shadow-pop ${TONES[item.tone] || TONES.info}`}
          >
            <p className="flex-1 leading-5">{item.message}</p>
            <button
              type="button"
              className="text-xs text-ink-faint hover:text-ink"
              onClick={() => remove(item.id)}
              aria-label="关闭提示"
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const value = useContext(ToastContext)
  if (!value) throw new Error('useToast 必须在 ToastProvider 内使用')
  return value
}
