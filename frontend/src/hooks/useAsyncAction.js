import { useCallback, useState } from 'react'

/** 管理面写操作的小状态机：busy 用一个字符串标识当前动作。 */
export function useAsyncAction() {
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)

  const run = useCallback(async (key, fn) => {
    setBusy(key)
    setError(null)
    try {
      return await fn()
    } catch (err) {
      setError(err)
      throw err
    } finally {
      setBusy(null)
    }
  }, [])

  return { busy, error, setError, run }
}
