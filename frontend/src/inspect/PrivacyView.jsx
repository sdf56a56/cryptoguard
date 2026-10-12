import { Badge, CopyButton } from '../components/ui.jsx'
import { TIER_BADGE } from '../console/badges.js'

// 隐私视角(spec §4.2)——「加密后到底发给了大模型什么」
// UI 零自算:所有字段原样来自 artifacts.outbound / artifacts.tokens,前端不做任何密码学计算。

// 收据行:label + 等宽值 + 复制
function ReceiptRow({ label, value }) {
  return (
    <div className="flex items-center gap-2 py-1">
      <span className="mono text-ink-faint shrink-0 w-28 text-[11px]">{label}</span>
      <span className="mono text-ink break-all bg-vault-50/60 px-2 py-1 rounded flex-1 border border-vault-100 text-[11px]">
        {value ?? '(无)'}
      </span>
      <CopyButton value={value ?? ''} />
    </div>
  )
}

// 文件双通道徽章:readable→可读通道 / evidence→存证通道(值来自 content_tier)
function FileChannelBadge({ tier }) {
  return tier === 'evidence' ? (
    <Badge color="violet">存证通道 · 恒不可读</Badge>
  ) : (
    <Badge color="vault">可读通道</Badge>
  )
}

export default function PrivacyView({ message = {}, artifacts = {} }) {
  const outbound = artifacts.outbound || {}
  const tokens = artifacts.tokens?.length ? artifacts.tokens : outbound.token_index || []
  const filePayloads = outbound.file_payloads || []
  const dump = JSON.stringify(outbound, null, 2)

  return (
    <div className="space-y-5">
      {/* 明文/出站并排 Diff:左本地明文(仅本机),右模型实际收到 */}
      <section>
        <div className="flex items-center gap-2 mb-2">
          <h2 className="text-[14px] font-semibold text-ink">明文 / 出站并排对照(Diff)</h2>
          <span className="text-[11px] text-ink-faint">左 = 本地明文,永不外发;右 = 模型实际收到的全部文本</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-line bg-surface">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
              <span className="text-[12px] font-semibold text-ink">本地明文(user_view)</span>
              <Badge color="gray">仅本机留存 · 不外发</Badge>
            </div>
            <pre className="px-4 py-3 mono text-[12px] text-ink whitespace-pre-wrap break-all">
              {message.user_view || '(无)'}
            </pre>
          </div>
          <div className="rounded-xl border border-vault-200 bg-vault-50/40">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-vault-200">
              <span className="text-[12px] font-semibold text-ink">模型实际收到(llm_view)</span>
              <Badge color="vault">出站即此文本</Badge>
            </div>
            <pre className="px-4 py-3 mono text-[12px] text-ink whitespace-pre-wrap break-all">
              {message.llm_view || '(无)'}
            </pre>
          </div>
        </div>
      </section>

      {/* 出站包收据卡 */}
      <section className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <h2 className="text-[13px] font-semibold text-ink">出站包收据(artifacts.outbound)</h2>
          <Badge color="vault">🔗 抗第二原像</Badge>
          <span className="ml-auto inline-flex items-center gap-1">
            <Badge color="warn">⏱ nonce + 5 分钟防重放窗</Badge>
          </span>
        </div>
        <div className="px-4 py-2">
          <ReceiptRow label="token_root" value={outbound.token_root} />
          <ReceiptRow label="input_hash" value={outbound.input_hash} />
          <ReceiptRow label="nonce" value={outbound.nonce} />
          <ReceiptRow label="timestamp" value={outbound.timestamp} />
          <div className="mt-2 pt-2 border-t border-line/70">
            <div className="text-[11px] font-semibold text-ink-soft mb-1.5">
              file_payloads 双通道({filePayloads.length} 个)
            </div>
            {filePayloads.length === 0 && (
              <div className="text-[11px] text-ink-faint">(本次出站无文件载荷)</div>
            )}
            {filePayloads.map((f, i) => (
              <div key={i} className="flex items-center gap-2 py-1 flex-wrap">
                <FileChannelBadge tier={f.content_tier} />
                <span className="mono text-[11px] text-ink">{f.filename_token}</span>
                <span className="mono text-[10px] text-ink-faint">
                  file_hash = {String(f.file_hash || '').slice(0, 16)}…
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 令牌清单:T1-T4 分级芯片 + leak_class 悬停卡 */}
      <section className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <h2 className="text-[13px] font-semibold text-ink">令牌清单(T1-T4 分级)</h2>
          <span className="text-[11px] text-ink-faint">悬停芯片查看泄漏函数声明 · 值全部来自后端</span>
        </div>
        <div className="p-4 flex items-start gap-2 flex-wrap">
          {tokens.length === 0 && <span className="text-[12px] text-ink-faint">(本次出站无令牌)</span>}
          {tokens.map((t, i) => {
            const meta = TIER_BADGE[t.tier] || TIER_BADGE.T1
            return (
              <div key={i} className="group relative">
                <span
                  className={`inline-flex items-center gap-1 px-2 py-1 rounded-full border text-[11px] mono ${meta.chip}`}
                >
                  <span className="font-semibold">{t.tier}</span>
                  {t.token}
                </span>
                {/* 悬停卡:泄漏函数声明(后端 leak_class 原样) */}
                <div className="invisible opacity-0 group-hover:visible group-hover:opacity-100 transition-opacity absolute left-0 top-full mt-1 w-72 z-20 rounded-lg border border-line bg-surface shadow-lift p-3 text-[11px] text-ink-soft space-y-1">
                  <div className="mono text-ink">令牌 {t.token}</div>
                  <div>类型 {t.type} · 级别 {meta.label}</div>
                  <div>
                    泄漏函数声明 leak_class = <span className="mono text-ink">{t.leak_class}</span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* LLM 视角原始 JSON:「这就是大模型看到的全部」 */}
      <details className="rounded-xl border border-line bg-paper">
        <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink flex items-center gap-2">
          <span>这就是大模型看到的全部</span>
          <span className="text-[11px] text-ink-faint font-normal">LLM 视角原始 JSON(出站包 dump,mono、可复制)</span>
        </summary>
        <div className="px-4 pb-4 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-ink-faint">artifacts.outbound(后端原样,前端不生成)</span>
            <CopyButton value={dump} className="ml-auto" />
          </div>
          <pre className="max-h-80 overflow-auto mono text-[11px] text-ink bg-surface border border-line rounded-lg p-3 whitespace-pre-wrap break-all">
            {dump}
          </pre>
        </div>
      </details>
    </div>
  )
}
