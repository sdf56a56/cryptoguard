import { Badge } from '../components/ui.jsx'

// 验收实测值卡(spec §6.3):值全部来自 /api/acceptance/* 真实响应,前端只格式化展示

const pct = (v) => (Number(v) * 100).toFixed(2) + '%'
const ci = (a) => '[' + (a || []).map((x) => Number(x).toFixed(4)).join(', ') + ']'

// 1. Golden Set 400 → 页内混淆矩阵卡(p/r/fpr + Wilson CI + per_type)
export function GoldenMatrixCard({ result }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-2.5 space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-[11px] font-semibold text-ink">混淆矩阵卡(Golden Set 400)</span>
        <Badge color="vault">Wilson 95% CI</Badge>
      </div>
      <div className="mono text-[11px] text-ink-soft">
        TP = {result.tp} · FP = {result.fp} · FN = {result.fn} · 负例单元 = {result.n_neg_units ?? '—'}
      </div>
      <table className="w-full text-[11px]">
        <thead>
          <tr className="text-left text-ink-faint border-b border-line">
            <th className="py-1 font-medium">指标</th>
            <th className="py-1 font-medium">实测</th>
            <th className="py-1 font-medium">Wilson 95% CI</th>
          </tr>
        </thead>
        <tbody>
          <tr className="border-b border-line/60">
            <td className="py-1 text-ink">准确率 P</td>
            <td className="py-1 mono text-vault-700">{pct(result.p)}</td>
            <td className="py-1 mono text-ink-soft">{ci(result.p_ci)}</td>
          </tr>
          <tr className="border-b border-line/60">
            <td className="py-1 text-ink">召回率 R</td>
            <td className="py-1 mono text-vault-700">{pct(result.r)}</td>
            <td className="py-1 mono text-ink-soft">{ci(result.r_ci)}</td>
          </tr>
          <tr>
            <td className="py-1 text-ink">误报率 FPR</td>
            <td className="py-1 mono text-vault-700">{pct(result.fpr)}</td>
            <td className="py-1 mono text-ink-soft">{ci(result.fpr_ci)}</td>
          </tr>
        </tbody>
      </table>
      {result.per_type && (
        <table className="w-full text-[11px]">
          <thead>
            <tr className="text-left text-ink-faint border-b border-line">
              <th className="py-1 font-medium">per_type</th>
              <th className="py-1 font-medium">TP</th>
              <th className="py-1 font-medium">FP</th>
              <th className="py-1 font-medium">FN</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(result.per_type).map(([t, c]) => (
              <tr key={t} className="border-b border-line/60">
                <td className="py-1 mono text-ink">{t}</td>
                <td className="py-1 mono text-ink-soft">{c.TP}</td>
                <td className="py-1 mono text-ink-soft">{c.FP}</td>
                <td className="py-1 mono text-ink-soft">{c.FN}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// 9. SEC-STORE-1 → {checked_files, checked_lines, leaks}:零泄漏绿色,有泄漏红色清单
export function StoreScanResult({ result }) {
  const leaks = result.leaks || []
  return (
    <div className="rounded-lg border border-line bg-surface p-2.5 space-y-1.5">
      <div className="mono text-[11px] text-ink-soft">
        checked_files = {result.checked_files} · checked_lines = {result.checked_lines}
      </div>
      {leaks.length === 0 ? (
        <Badge color="ok">检出 0 明文 · 落盘干净(仅 llm_view / *_ct)</Badge>
      ) : (
        <div className="rounded-lg border border-bad/40 bg-bad-soft p-2">
          <div className="text-[11px] font-semibold text-bad">检出 {leaks.length} 处明文键泄漏</div>
          <div className="mt-1 space-y-0.5">
            {leaks.map((l, i) => (
              <div key={i} className="mono text-[10px] text-bad break-all">
                {l.file}:{l.line} → {l.path}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// 10. SEC-REPLAY-1 → ok + 计数,或红色 error + kind
export function ReplayResult({ result }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-2.5 space-y-1.5">
      {result.ok ? (
        <>
          <Badge color="ok">回放重建成功(只读)</Badge>
          <div className="mono text-[11px] text-ink-soft">
            链条目 {result.chain_entries} · 会话 {result.sessions} · 消息 {result.messages}
          </div>
        </>
      ) : (
        <>
          <Badge color="bad">回放失败</Badge>
          <div className="text-[11px] text-bad">{result.error}</div>
          <div className="mono text-[10px] text-bad/80">kind = {result.kind}</div>
        </>
      )}
    </div>
  )
}

// 11. SEC-DEGRADE-1 → 三分类注入返回三元组逐字段展示
export function DegradeResult({ result }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-2.5 space-y-1">
      <div className="mono text-[11px] text-ink break-all">kind = {String(result.kind)}</div>
      <div className="mono text-[11px] text-ink break-all">ui_class = {String(result.ui_class)}</div>
      <div className="mono text-[11px] text-ink break-all">degraded = {String(result.degraded)}</div>
      <div className="mono text-[11px] text-ink break-all">incomplete = {String(result.incomplete)}</div>
    </div>
  )
}

// 按行分发实测值卡
export function AcceptanceResult({ rowId, result }) {
  if (!result) return null
  if (result.status === 'running') {
    return <div className="text-[11px] text-ink-faint">运行中…</div>
  }
  if (result.status === 'error') {
    return (
      <div className="rounded-lg border border-bad/40 bg-bad-soft px-2.5 py-2 text-[11px] text-bad">
        请求失败:{result.error}
      </div>
    )
  }
  const data = result.data
  switch (rowId) {
    case 'golden-set':
      return <GoldenMatrixCard result={data} />
    case 'sec-store':
      return <StoreScanResult result={data} />
    case 'sec-replay':
      return <ReplayResult result={data} />
    case 'sec-degrade':
      return <DegradeResult result={data} />
    default:
      return (
        <pre className="mono text-[10px] text-ink-soft bg-paper border border-line rounded-lg p-2 whitespace-pre-wrap break-all">
          {JSON.stringify(data, null, 2)}
        </pre>
      )
  }
}
