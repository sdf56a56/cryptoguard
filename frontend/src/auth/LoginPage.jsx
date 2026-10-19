import { useCallback, useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { api } from '../api/endpoints.js'
import { useAuth } from './AuthContext.jsx'
import { Icon } from '../components/Icon.jsx'
import { Badge, Button, Field, Input, Spinner } from '../components/ui.jsx'

export default function LoginPage() {
  const { status, error: authError, login, retry } = useAuth()
  const [health, setHealth] = useState({ loading: true, data: null, error: null })
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState(null)

  const loadHealth = useCallback(async () => {
    setHealth({ loading: true, data: null, error: null })
    try {
      const data = await api.health()
      setHealth({ loading: false, data, error: null })
    } catch (error) {
      setHealth({ loading: false, data: null, error })
    }
  }, [])

  useEffect(() => {
    loadHealth()
  }, [loadHealth])

  if (status === 'authenticated') return <Navigate to="/" replace />
  if (status === 'checking') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas">
        <div className="flex items-center gap-3 text-[13px] text-ink-soft">
          <Spinner size={18} />
          正在校验管理员令牌…
        </div>
      </div>
    )
  }

  const healthError = health.error
  const unavailable = healthError?.status === 503
  const adminConfigured = health.data?.auth?.admin_configured !== false
  const showSetup = !health.loading && (!adminConfigured || unavailable)
  const showConnectionError = Boolean(healthError) && healthError.status === 0

  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setFormError(null)
    try {
      await login(token)
    } catch (error) {
      setFormError(error)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-canvas px-4 py-10">
      <div className="w-full max-w-[440px]">
        <div className="mb-6 flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-ink text-white">
            <Icon name="shield" size={19} />
          </span>
          <div>
            <h1 className="text-[18px] font-semibold tracking-tight text-ink">CryptoGuard 控制台</h1>
            <p className="text-[12px] text-ink-faint">安全中转网关 · 运维与管理面</p>
          </div>
        </div>

        <div className="rounded-lg border border-line bg-surface p-6 shadow-card">
          {health.loading ? (
            <div className="flex items-center gap-3 py-6 text-[13px] text-ink-soft">
              <Spinner size={16} />
              正在连接网关…
            </div>
          ) : showConnectionError ? (
            <div>
              <h2 className="text-[15px] font-semibold text-ink">无法连接网关</h2>
              <p className="mt-2 text-[12.5px] leading-5 text-ink-soft">
                {healthError.message}
              </p>
              <ol className="mt-3 list-decimal space-y-1 pl-5 text-[12px] text-ink-soft">
                <li>确认后端已启动：<code className="mono">./start.sh</code>，默认监听 127.0.0.1:8100</li>
                <li>确认 Vite 代理目标：默认 <code className="mono">http://127.0.0.1:8100</code>，可用 <code className="mono">CG_API_TARGET</code> 覆盖</li>
                <li>确认浏览器访问的是控制台地址而不是后端端口</li>
              </ol>
              <Button className="mt-4" icon="refresh" onClick={loadHealth}>重新连接</Button>
            </div>
          ) : showSetup ? (
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-[15px] font-semibold text-ink">管理面尚未启用</h2>
                <Badge tone="warn">需要配置</Badge>
              </div>
              <p className="mt-2 text-[12.5px] leading-5 text-ink-soft">
                {unavailable
                  ? (healthError?.body?.detail || '网关尚未完成装配，请查看后端启动日志。')
                  : '网关正在运行，但没有设置管理员令牌。'}
              </p>
              <div className="mt-4 rounded-md border border-line bg-canvas p-3">
                <p className="text-[11.5px] font-medium text-ink">在 backend/.env 中设置</p>
                <pre className="mono mt-2 overflow-x-auto text-[11.5px] leading-5 text-ink-soft">
{`CG_ADMIN_TOKEN=<至少 16 字符的随机令牌>
# 如需控制台直接管理上游，可留空 CG_PROVIDERS，
# 登录后在「上游配置」里创建 Provider。`}
                </pre>
              </div>
              <ol className="mt-3 list-decimal space-y-1 pl-5 text-[12px] text-ink-soft">
                <li>保存后重启网关进程</li>
                <li>刷新本页，输入同一个令牌登录</li>
              </ol>
              <div className="mt-4 flex gap-2">
                <Button icon="refresh" onClick={loadHealth}>重新检测</Button>
                <Button variant="ghost" onClick={() => window.open('/health', '_blank', 'noopener')}>
                  查看 /health
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={submit}>
              <h2 className="text-[15px] font-semibold text-ink">登录管理面</h2>
              <p className="mt-1 text-[12px] leading-5 text-ink-soft">
                平台只有一个全权管理员账号。请输入后端 <code className="mono">CG_ADMIN_TOKEN</code>。
              </p>
              <Field label="管理员令牌" className="mt-4">
                <Input
                  type="password"
                  autoComplete="off"
                  autoFocus
                  placeholder="X-Admin-Token"
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  mono
                />
              </Field>
              {formError ? (
                <p className="mt-2 text-[12px] text-bad">{formError.message}</p>
              ) : null}
              {authError ? (
                <div className="mt-2 text-[12px] text-bad">
                  {authError.message}
                  {authError.status === 0 ? (
                    <button type="button" className="ml-2 underline" onClick={retry}>重试</button>
                  ) : null}
                </div>
              ) : null}
              <Button
                type="submit"
                variant="primary"
                className="mt-4 w-full"
                busy={busy}
                disabled={!token.trim()}
              >
                登录
              </Button>
              <p className="mt-3 text-[11px] leading-4 text-ink-faint">
                令牌只保存在当前标签页的 sessionStorage，不写入 localStorage，也不会出现在 URL 中。
              </p>
            </form>
          )}
        </div>

        {health.data ? (
          <div className="mt-4 grid grid-cols-2 gap-2 text-[11px] text-ink-faint">
            <span>版本：<span className="mono text-ink-soft">{health.data.version || '—'}</span></span>
            <span>环境：<span className="mono text-ink-soft">{health.data.env || '—'}</span></span>
            <span>Provider：<span className="mono text-ink-soft">{health.data.providers?.length ?? 0}</span></span>
            <span>客户端密钥：<span className="mono text-ink-soft">{health.data.auth?.client_keys ?? 0}</span></span>
          </div>
        ) : null}
      </div>
    </div>
  )
}
