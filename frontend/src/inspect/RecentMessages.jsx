import { Link } from 'react-router-dom'
import { Badge } from '../components/ui.jsx'
import { SkeletonState } from './states.jsx'

// 「最近消息」选择列表(直接 URL 访问 /inspect 时的入口,spec §4.2)
export default function RecentMessages({ loading = false, items = [], error = null }) {
  return (
    <section className="rounded-xl border border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-line/70">
        <h2 className="text-[14px] font-semibold text-ink">最近消息</h2>
        <span className="text-[11px] text-ink-faint">
          选择一条消息进入双视角查看器,或从 /chat 对话气泡的「查看过程」点入
        </span>
      </div>
      <div className="p-4">
        {loading && <SkeletonState />}
        {!loading && error && (
          <div className="rounded-lg border border-bad/40 bg-bad-soft px-3 py-2 text-[12px] text-bad">
            最近消息加载失败:{error}
          </div>
        )}
        {!loading && !error && items.length === 0 && (
          <div className="text-center py-8">
            <div className="text-[13px] text-ink-soft">暂无消息</div>
            <Link to="/chat" className="mt-3 inline-flex text-[12px] text-vault-700 hover:underline">
              去 /chat 发一条 →
            </Link>
          </div>
        )}
        {!loading && !error && items.length > 0 && (
          <div className="space-y-1.5">
            {items.map((m) => (
              <Link
                key={m.id}
                to={`/inspect/${m.id}`}
                className="flex items-center gap-2 rounded-lg border border-line bg-paper px-3 py-2 hover:border-vault-300 hover:bg-vault-50/40 transition-colors"
              >
                <Badge color={m.role === 'user' ? 'vault' : 'gray'}>{m.role}</Badge>
                <span className="text-[11px] text-ink-soft truncate w-32">{m.title || m.session_id}</span>
                <span className="text-[11px] text-ink-faint mono shrink-0">{m.ts}</span>
                <span className="text-[12px] text-ink truncate flex-1">{m.snippet}</span>
                <span className="text-[11px] text-vault-700 whitespace-nowrap">查看 →</span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
