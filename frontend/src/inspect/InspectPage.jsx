import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { Badge } from '../components/ui.jsx'
import PrivacyView from './PrivacyView.jsx'
import AuditView from './AuditView.jsx'
import RecentMessages from './RecentMessages.jsx'
import { SkeletonState, NotFoundState, IncompleteBar, MockDegradedBadge } from './states.jsx'

// /inspect/:messageId?(spec §4.2):视角 Tab + 消息定位条 + 直接访问「最近消息」列表
// 六失败态:骨架屏/消息不存在/链条目缺失/校验失败(→AuditView)/不完整/Mock 降级(本页横幅)
export default function InspectPage() {
  const { messageId } = useParams()
  const [view, setView] = useState('privacy')
  const [pipeline, setPipeline] = useState(null)
  const [loading, setLoading] = useState(Boolean(messageId))
  const [loadError, setLoadError] = useState(null) // {notFound, message}
  const [turn, setTurn] = useState(null)
  const [recent, setRecent] = useState({ loading: false, items: [], error: null })

  // 消息管线(GET /api/messages/{mid}/pipeline)
  useEffect(() => {
    if (!messageId) return undefined
    let alive = true
    setLoading(true)
    setPipeline(null)
    setLoadError(null)
    setTurn(null)
    api
      .messagePipeline(messageId)
      .then((p) => {
        if (!alive) return
        setPipeline(p)
        setLoading(false)
      })
      .catch((e) => {
        if (!alive) return
        const msg = String(e?.message || e)
        setLoadError({ notFound: /^404/.test(msg), message: msg })
        setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [messageId])

  // 轮次定位:会话消息序号(计数展示,非密码学计算)
  useEffect(() => {
    const sid = pipeline?.message?.session_id
    const mid = pipeline?.message?.id
    if (!sid || !mid) return undefined
    let alive = true
    api
      .getSession(sid)
      .then((d) => {
        if (!alive) return
        const idx = (d.messages || []).findIndex((m) => m.id === mid)
        if (idx >= 0) setTurn(idx + 1)
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [pipeline?.message?.id, pipeline?.message?.session_id])

  // 直接访问(无 id):最近消息列表(GET /api/chat/sessions + messages)
  useEffect(() => {
    if (messageId) return undefined
    let alive = true
    setRecent({ loading: true, items: [], error: null })
    ;(async () => {
      try {
        const sessions = (await api.listSessions()) || []
        const details = await Promise.all(
          sessions.map((s) => api.getSession(s.id).catch(() => null)),
        )
        const items = []
        for (const d of details) {
          if (!d) continue
          for (const m of d.messages || []) {
            items.push({
              id: m.id,
              session_id: m.session_id,
              title: d.session?.title || m.session_id,
              role: m.role,
              ts: m.ts,
              snippet: String(m.llm_view || '').slice(0, 60),
            })
          }
        }
        items.sort((a, b) => (a.ts < b.ts ? 1 : -1))
        if (alive) setRecent({ loading: false, items: items.slice(0, 20), error: null })
      } catch (e) {
        if (alive) setRecent({ loading: false, items: [], error: String(e?.message || e) })
      }
    })()
    return () => {
      alive = false
    }
  }, [messageId])

  const message = pipeline?.message || null
  const replyMeta = message?.reply_meta || {}
  const verification = pipeline?.verification || []

  return (
    <div className="mx-auto max-w-[1280px] px-6 py-8">
      <div className="flex items-center gap-3">
        <h1 className="display text-[22px] font-bold text-ink">查看器 · 双视角</h1>
        <Badge color="gray">UI 零自算</Badge>
        <Link
          to="/chat"
          className="ml-auto inline-flex items-center px-3.5 py-1.5 rounded-lg border border-line bg-surface text-[12px] text-ink hover:border-vault-300 hover:text-vault-700"
        >
          返回对话
        </Link>
      </div>

      {!messageId && (
        <div className="mt-5">
          <RecentMessages loading={recent.loading} items={recent.items} error={recent.error} />
        </div>
      )}

      {messageId && (
        <>
          {/* 消息定位条:会话/轮次/角色/时间 */}
          <div className="mt-4 flex items-center gap-2 flex-wrap rounded-xl border border-line bg-surface px-4 py-2.5 text-[11px]">
            <span className="text-ink-faint">消息定位</span>
            <span className="text-ink-faint">会话</span>
            <span className="mono text-ink bg-vault-50 px-2 py-0.5 rounded border border-vault-100">
              {message ? message.session_id : '—'}
            </span>
            <span className="text-ink-faint">轮次</span>
            <span className="mono text-ink">{turn ? `#${turn}` : '—'}</span>
            <span className="text-ink-faint">角色</span>
            <span className="mono text-ink">{message ? message.role : '—'}</span>
            <span className="text-ink-faint">时间</span>
            <span className="mono text-ink">{message ? message.ts : '—'}</span>
            <span className="text-ink-faint">消息 id</span>
            <span className="mono text-ink bg-vault-50 px-2 py-0.5 rounded border border-vault-100">
              {messageId}
            </span>
          </div>

          {/* 视角 Tab:【隐私视角】【审计视角】 */}
          <div className="mt-4 inline-flex items-center gap-1 rounded-lg border border-line bg-surface p-1">
            {[
              ['privacy', '【隐私视角】'],
              ['audit', '【审计视角】'],
            ].map(([key, label]) => (
              <button
                key={key}
                onClick={() => setView(key)}
                className={`px-4 py-1.5 rounded-md text-[13px] font-semibold transition-colors ${
                  view === key
                    ? 'bg-vault-500 text-white'
                    : 'text-ink-soft hover:text-vault-700 hover:bg-vault-50'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* 失败态横幅:⑤ 不完整黄条 / ⑥ Mock 降级黄徽章 */}
          <div className="mt-4 space-y-2">
            {replyMeta.incomplete && <IncompleteBar />}
            {replyMeta.degraded && <MockDegradedBadge degraded={replyMeta.degraded} />}
          </div>

          <div className="mt-4">
            {loading && <SkeletonState />}
            {loadError?.notFound && <NotFoundState messageId={messageId} />}
            {loadError && !loadError.notFound && (
              <div className="rounded-xl border border-bad/40 bg-bad-soft px-4 py-3 text-[13px] text-bad">
                查看器数据加载失败:{loadError.message}
              </div>
            )}
            {message && view === 'privacy' && (
              <PrivacyView message={message} artifacts={pipeline.artifacts || {}} />
            )}
            {message && view === 'audit' && (
              <AuditView
                key={message.id}
                message={message}
                artifacts={pipeline.artifacts || {}}
                verification={verification}
                chainEntries={pipeline.chain_entries || []}
              />
            )}
          </div>
        </>
      )}
    </div>
  )
}
