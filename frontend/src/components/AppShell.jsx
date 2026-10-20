import { useMemo, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'
import { api } from '../api/endpoints.js'
import { useResource } from '../hooks/useResource.js'
import { Icon } from './Icon.jsx'
import { Badge, Button } from './ui.jsx'

const NAV = [
  { to: '/', label: '概览', icon: 'dashboard', end: true },
  { to: '/requests', label: '请求日志', icon: 'list' },
  { to: '/confirmations', label: '待确认', icon: 'check' },
  { to: '/clients', label: '客户端密钥', icon: 'key' },
  { to: '/upstreams', label: '上游配置', icon: 'server' },
  { to: '/policies', label: '策略与审计', icon: 'shield' },
  { to: '/playground', label: '链路测试', icon: 'terminal' },
]

const TITLES = [
  [/^\/requests\/[^/]+$/, '请求详情'],
  [/^\/requests\/?$/, '请求日志'],
  [/^\/confirmations/, '待确认'],
  [/^\/clients/, '客户端密钥'],
  [/^\/upstreams/, '上游配置'],
  [/^\/policies/, '策略与审计'],
  [/^\/playground/, '链路测试'],
  [/^\/?$/, '概览'],
]

function titleFor(pathname) {
  for (const [pattern, title] of TITLES) {
    if (pattern.test(pathname)) return title
  }
  return 'CryptoGuard'
}

function NavItems({ pending, onNavigate }) {
  return (
    <nav className="space-y-0.5 px-2.5">
      {NAV.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          onClick={onNavigate}
          className={({ isActive }) => [
            'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] transition-colors',
            isActive
              ? 'bg-accent-50 font-medium text-accent-700'
              : 'text-ink-soft hover:bg-canvas hover:text-ink',
          ].join(' ')}
        >
          <Icon name={item.icon} size={16} />
          <span className="flex-1">{item.label}</span>
          {item.to === '/confirmations' && pending > 0 ? (
            <span className="tabular rounded-full bg-warn-soft px-1.5 py-0.5 text-[10px] font-semibold text-warn">
              {pending}
            </span>
          ) : null}
        </NavLink>
      ))}
    </nav>
  )
}

export default function AppShell() {
  const { logout } = useAuth()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const title = useMemo(() => titleFor(location.pathname), [location.pathname])

  const pending = useResource(
    () => api.confirmations.list({ status: 'pending', limit: 1 }),
    [],
    { pollMs: 20000 },
  )
  const pendingCount = Number(pending.data?.stats?.pending || 0)

  const health = useResource(() => api.health(), [], { pollMs: 60000 })
  const online = Boolean(health.data) && !health.error
  const env = health.data?.env || ''

  return (
    <div className="min-h-screen bg-canvas">
      {/* 桌面侧栏 */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-56 flex-col border-r border-line bg-surface lg:flex">
        <div className="flex h-14 items-center gap-2.5 border-b border-line px-4">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-ink text-white">
            <Icon name="shield" size={16} />
          </span>
          <div className="leading-tight">
            <div className="text-[13.5px] font-semibold text-ink">CryptoGuard</div>
            <div className="text-[10.5px] text-ink-faint">安全中转控制台</div>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto py-3">
          <div className="mb-1 px-4 text-[10.5px] font-medium uppercase tracking-wide text-ink-faint">
            运行
          </div>
          <NavItems pending={pendingCount} />
        </div>
        <div className="border-t border-line p-3">
          <div className="mb-2 flex items-center justify-between px-1 text-[11px] text-ink-faint">
            <span className="inline-flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${online ? 'bg-ok' : 'bg-bad'}`} />
              {online ? '网关在线' : '网关不可达'}
            </span>
            {env ? <span className="mono">{env}</span> : null}
          </div>
          <button
            type="button"
            onClick={logout}
            className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-[12px] text-ink-soft hover:bg-canvas hover:text-ink"
          >
            <Icon name="logout" size={14} />
            退出登录
          </button>
        </div>
      </aside>

      {/* 移动端抽屉 */}
      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            aria-label="关闭导航"
            className="absolute inset-0 bg-ink/35"
            onClick={() => setMobileOpen(false)}
          />
          <div className="relative flex h-full w-64 flex-col border-r border-line bg-surface shadow-pop">
            <div className="flex h-14 items-center justify-between border-b border-line px-4">
              <span className="text-[13px] font-semibold text-ink">CryptoGuard</span>
              <button type="button" onClick={() => setMobileOpen(false)} aria-label="关闭">
                <Icon name="x" size={18} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto py-3">
              <NavItems pending={pendingCount} onNavigate={() => setMobileOpen(false)} />
            </div>
            <div className="border-t border-line p-3">
              <Button variant="ghost" size="sm" icon="logout" onClick={logout} className="w-full justify-start">
                退出登录
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      <div className="lg:pl-56">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-surface/95 px-4 backdrop-blur lg:px-6">
          <button
            type="button"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-ink-soft hover:bg-canvas lg:hidden"
            onClick={() => setMobileOpen(true)}
            aria-label="打开导航"
          >
            <Icon name="menu" size={18} />
          </button>
          <div className="flex min-w-0 items-center gap-1.5 text-[13px]">
            <span className="hidden text-ink-faint sm:inline">CryptoGuard</span>
            <span className="hidden text-line-strong sm:inline">/</span>
            <span className="truncate font-medium text-ink">{title}</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge tone={online ? 'ok' : 'bad'} dot>
              {online ? '运行中' : '连接中断'}
            </Badge>
            {env ? <Badge tone="neutral" className="hidden sm:inline-flex">{env}</Badge> : null}
            <span className="mono hidden text-[11px] text-ink-faint md:inline">
              {health.data?.deployment?.mode || ''}
            </span>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1560px]">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
