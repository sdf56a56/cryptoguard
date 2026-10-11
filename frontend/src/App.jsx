import { Routes, Route, NavLink, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import Home from './pages/Home'
import Chat from './pages/Chat'
import Detect from './pages/Detect'
import Entities from './pages/Entities'
import Pipeline from './pages/Pipeline'
import Outbound from './pages/Outbound'
import Verify from './pages/Verify'
import Attack from './pages/Attack'
import Audit from './pages/Audit'
import Perf from './pages/Perf'
import Compliance from './pages/Compliance'
import CryptoLab from './pages/CryptoLab'

const NAV = [
  { to: '/', label: '概览', icon: '◈' },
  { to: '/chat', label: '安全对话', icon: '💬' },
  { to: '/detect', label: '输入脱敏', icon: '✂️' },
  { to: '/entities', label: '实体与策略', icon: '🗂️' },
  { to: '/pipeline', label: '密码流水线', icon: '🔐' },
  { to: '/outbound', label: '出站请求', icon: '📡' },
  { to: '/verify', label: '响应验证', icon: '✓' },
  { to: '/attack', label: '攻击演示', icon: '⚠️' },
  { to: '/audit', label: '审计日志', icon: '⛓️' },
  { to: '/lab', label: '密码实验室', icon: '🧪' },
  { to: '/perf', label: '性能仪表盘', icon: '📊' },
  { to: '/compliance', label: '合规映射', icon: '📜' },
]

function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-60 border-r border-line bg-surface z-40 flex flex-col">
      <Link to="/" className="flex items-center gap-3 px-5 py-5 border-b border-line">
        <div className="h-10 w-10 rounded-xl bg-vault-500 flex items-center justify-center shadow-[0_2px_10px_-2px_rgba(67,97,238,0.5)]">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2 L20 5 V11 C20 16 16.5 20 12 22 C7.5 20 4 16 4 11 V5 Z"/>
            <path d="M9 12 L11 14 L15 9"/>
          </svg>
        </div>
        <div>
          <div className="display font-bold text-ink leading-tight text-[15px]">CryptoGuard</div>
          <div className="text-[10px] text-ink-faint">大模型敏感数据防泄漏平台</div>
        </div>
      </Link>
      <nav className="flex-1 overflow-y-auto py-3 px-2.5 space-y-0.5">
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-3 py-2 rounded-lg text-[13px] transition-colors ${
                isActive
                  ? 'bg-vault-50 text-vault-700 font-semibold border border-vault-200'
                  : 'text-ink-soft hover:text-ink hover:bg-paper border border-transparent'
              }`
            }
          >
            <span className="w-5 text-center">{n.icon}</span>
            {n.label}
          </NavLink>
        ))}
      </nav>
      <div className="px-5 py-4 border-t border-line">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-ok animate-pulse" />
          <span className="text-[10px] text-ink-faint">CG-ABE-SSE · 四层可验证代理</span>
        </div>
      </div>
    </aside>
  )
}

export default function App() {
  return (
    <div className="min-h-screen bg-paper text-ink">
      <Sidebar />
      <main className="ml-60">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.35 }}
        >
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/chat" element={<Chat />} />
            <Route path="/detect" element={<Detect />} />
            <Route path="/entities" element={<Entities />} />
            <Route path="/pipeline" element={<Pipeline />} />
            <Route path="/outbound" element={<Outbound />} />
            <Route path="/verify" element={<Verify />} />
            <Route path="/attack" element={<Attack />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/lab" element={<CryptoLab />} />
            <Route path="/perf" element={<Perf />} />
            <Route path="/compliance" element={<Compliance />} />
          </Routes>
        </motion.div>
      </main>
    </div>
  )
}
