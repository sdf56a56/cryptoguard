import { NavLink, Outlet } from 'react-router-dom'

// 极简顶栏(spec §4.0):产品标记 + 三入口切换,浅底大留白、单一靛蓝主色
const NAV = [
  { to: '/chat', label: '对话' },
  { to: '/inspect', label: '查看器' },
  { to: '/demo', label: '演示' },
]

export default function AppShell() {
  return (
    <div className="min-h-screen bg-paper text-ink">
      <header className="sticky top-0 z-40 border-b border-line bg-surface/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-[1280px] items-center gap-6 px-6">
          <NavLink to="/chat" className="flex items-center gap-2">
            <span className="h-8 w-8 rounded-lg bg-vault-500 text-white flex items-center justify-center text-sm font-bold">
              CG
            </span>
            <span className="display text-[17px] font-bold tracking-tight text-ink">CryptoGuard</span>
          </NavLink>

          <nav className="flex items-center gap-1">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                className={({ isActive }) =>
                  `px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-colors ${
                    isActive
                      ? 'bg-vault-50 text-vault-700 border border-vault-200'
                      : 'text-ink-soft hover:text-vault-700 border border-transparent'
                  }`
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      <main>
        <Outlet />
      </main>
    </div>
  )
}
