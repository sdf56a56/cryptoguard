import { Link } from 'react-router-dom'

// 六失败态线框(spec §4.2):骨架屏 / 消息不存在 / 链条目缺失 / 校验失败 / 不完整 / Mock 降级
// 状态色语义:红=失败、黄=降级·不完整、灰=无数据(§4.0 全局统一)

// ① 载入中:骨架屏
export function SkeletonState({ label = '载入中' }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-8" aria-busy="true">
      <div className="text-[13px] text-ink-faint mb-4">{label}…</div>
      <div className="space-y-3">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-4 rounded bg-paper animate-pulse" style={{ width: `${90 - i * 18}%` }} />
        ))}
      </div>
    </div>
  )
}

// ② 消息不存在:空态 + 返回
export function NotFoundState({ messageId }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-10 text-center">
      <div className="text-[40px] leading-none text-ink-faint">∅</div>
      <div className="mt-3 text-[15px] font-semibold text-ink">消息不存在</div>
      <div className="mt-2 text-[12px] text-ink-soft">
        未找到消息{' '}
        <span className="mono text-ink bg-vault-50 px-2 py-0.5 rounded border border-vault-100">{messageId}</span>
        (已从存储中查询,返回 404)
      </div>
      <Link
        to="/chat"
        className="mt-5 inline-flex items-center px-4 py-2 rounded-lg border border-line bg-paper text-sm text-ink hover:border-vault-300 hover:text-vault-700"
      >
        返回对话
      </Link>
    </div>
  )
}

// ③ 链条目缺失:红框定位缺失 index(数据缺失不造数)
export function ChainEntryMissingState({ missing = [] }) {
  return (
    <div className="rounded-xl border-2 border-bad bg-bad-soft p-4 alert-pulse">
      <div className="text-[13px] font-semibold text-bad">链条目缺失</div>
      <div className="mt-2 flex items-center gap-2 flex-wrap">
        <span className="text-[11px] text-bad">缺失 index:</span>
        {missing.map((i) => (
          <span key={i} className="mono text-[12px] text-bad bg-surface border border-bad/40 rounded px-2 py-0.5">
            #{i}
          </span>
        ))}
      </div>
      <div className="mt-2 text-[11px] text-bad/80">
        该消息 chain_refs 引用的链条目不在当前链上(数据缺失,不造数)——请核对数据目录或重新回放。
      </div>
    </div>
  )
}

// ④ 校验失败:红态定位到失败层
export function VerificationFailedState({ layers = [] }) {
  return (
    <div className="rounded-xl border-2 border-bad bg-bad-soft p-4">
      <div className="text-[13px] font-semibold text-bad">校验失败</div>
      <div className="mt-2 space-y-1.5">
        {layers.map((l, i) => (
          <div key={i} className="flex items-start gap-2 text-[12px]">
            <span className="mono text-bad font-semibold shrink-0">{l.layer}</span>
            <span className="text-bad/90">{l.detail}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ⑤ 不完整回复:黄条
export function IncompleteBar({ detail }) {
  return (
    <div className="rounded-lg border border-warn/40 bg-warn-soft px-4 py-2.5 text-[12px] text-warn flex items-center gap-2">
      <Badge>⚠</Badge>
      <span className="font-semibold">回复不完整</span>
      <span className="text-warn/90">{detail || '流中断 · 已收内容保留(reply_meta.incomplete = true)'}</span>
    </div>
  )
}

// ⑥ Mock 降级:黄徽章
export function MockDegradedBadge({ degraded = 'mock' }) {
  return (
    <div className="inline-flex items-center gap-2">
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-warn/40 bg-warn-soft text-warn text-[12px] font-semibold">
        Mock 降级
      </span>
      <span className="text-[11px] text-warn/90">
        已切换模拟回复(reply_meta.degraded = <span className="mono">{String(degraded)}</span>)
      </span>
    </div>
  )
}

// 小圆点(黄条前缀)
function Badge({ children }) {
  return <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-warn/40 bg-surface text-warn text-[11px]">{children}</span>
}
