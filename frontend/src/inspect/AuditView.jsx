import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { Badge, CopyButton } from '../components/ui.jsx'
import { ChainEntryMissingState, VerificationFailedState } from './states.jsx'
import RecomputePanel from './RecomputePanel.jsx'

// 审计视角(spec §4.2)——「背后逻辑」:流水线时间线 / 哈希链定位 / Merkle 证明 /
// 独立复算 / 四层验证 / reasoning 密文。UI 零自算,缺失数据不造数。

// entry_type → 四色(spec §4.2 链窗口)
const ENTRY_COLOR = {
  USER_OVERRIDE: 'warn',
  FILE_COMMIT: 'violet',
  QUERY: 'vault',
  RESPONSE: 'ok',
}

// 等宽数据行(哈希/签名展示 + 复制)
function MonoRow({ label, value }) {
  return (
    <div className="flex items-center gap-2 py-1">
      <span className="mono text-ink-faint shrink-0 w-32 text-[11px]">{label}</span>
      <span className="mono text-ink break-all bg-vault-50/60 px-2 py-1 rounded flex-1 border border-vault-100 text-[11px]">
        {value ?? '(无)'}
      </span>
      <CopyButton value={value ?? ''} />
    </div>
  )
}

// 流水线时间线:有分阶段耗时按段渲染;无则不造数,落回验证层与收据字段
export function PipelineTimeline({ artifacts = {}, message = {} }) {
  const stages = Array.isArray(artifacts.pipeline)
    ? artifacts.pipeline
    : Array.isArray(artifacts.stages)
      ? artifacts.stages
      : null
  const replyMeta = message.reply_meta || {}
  return (
    <section className="rounded-xl border border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
        <h2 className="text-[13px] font-semibold text-ink">流水线时间线(八阶段)</h2>
        <span className="text-[11px] text-ink-faint">数值原样来自后端,前端零自算</span>
      </div>
      <div className="p-4 space-y-2">
        {stages && stages.length > 0 ? (
          stages.map((s, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px]">
              <span className="mono text-ink w-40">{s.step || s.name || `阶段${i + 1}`}</span>
              <span className="mono text-vault-700">{s.ms ?? s.elapsed_ms ?? '—'} ms</span>
              <span className="text-ink-faint">{s.meta ? JSON.stringify(s.meta) : ''}</span>
            </div>
          ))
        ) : (
          <>
            <div className="rounded-lg border border-line bg-paper px-3 py-2 text-[11px] text-ink-soft">
              本消息未记录分阶段耗时(数据缺失不造数)——以验证层与出站收据字段为准,展示如下。
            </div>
            {/* 回落:验证 4 行 + reply_meta + response_hash/signature(后端 artifacts 原样) */}
            <div className="flex items-center gap-2 flex-wrap text-[11px]">
              <span className="text-ink-faint">reply_meta:</span>
              <span className="mono text-ink bg-paper border border-line rounded px-2 py-0.5">
                model = {String(replyMeta.model ?? '—')}
              </span>
              <span className="mono text-ink bg-paper border border-line rounded px-2 py-0.5">
                incomplete = {String(replyMeta.incomplete ?? false)}
              </span>
              <span className="mono text-ink bg-paper border border-line rounded px-2 py-0.5">
                degraded = {String(replyMeta.degraded ?? '—')}
              </span>
            </div>
            {artifacts.response_hash != null && (
              <MonoRow label="response_hash" value={artifacts.response_hash} />
            )}
            {artifacts.signature != null && <MonoRow label="signature" value={artifacts.signature} />}
            {artifacts.response_hash == null && artifacts.signature == null && (
              <div className="text-[11px] text-ink-faint">
                (用户消息记录无 response_hash/signature —— 响应收据存于 assistant 消息记录)
              </div>
            )}
          </>
        )}
      </div>
    </section>
  )
}

// 哈希链定位:chain_refs 高亮窗口 + 消息↔链双向跳转
export function ChainWindow({ refs = [], entries = [], messageId }) {
  const refSet = new Set(refs)
  return (
    <div className="space-y-1.5">
      {entries.length === 0 && (
        <div className="text-[11px] text-ink-faint">(链窗口为空 — 本消息未入链或链数据未加载)</div>
      )}
      {entries.map((e) => {
        const isRef = refSet.has(e.index)
        return (
          <div
            key={e.index}
            id={`chain-entry-${e.index}`}
            className={`flex items-center gap-2 flex-wrap rounded-lg border px-3 py-2 text-[11px] ${
              isRef
                ? 'border-vault-500 ring-2 ring-vault-500/40 bg-vault-50/60'
                : 'border-line bg-paper'
            }`}
          >
            <span className="mono text-ink font-semibold w-10">#{e.index}</span>
            <Badge color={ENTRY_COLOR[e.entry_type] || 'gray'}>{e.entry_type}</Badge>
            {isRef && <Badge color="vault">本消息条目</Badge>}
            <span className="mono text-ink-soft break-all">
              digest {String(e.payload_digest || '').slice(0, 20)}…
            </span>
            <span className="mono text-ink-soft break-all">
              hash {String(e.hash || '').slice(0, 20)}…
            </span>
            <span className="text-ink-faint">{e.timestamp}</span>
            {e.message_id && (
              <span className="ml-auto flex items-center gap-2">
                <span className="mono text-ink-faint">{e.message_id}</span>
                <Link
                  to={`/inspect/${e.message_id}`}
                  className="text-vault-700 hover:underline whitespace-nowrap"
                >
                  查看消息 ⇄
                </Link>
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}

// Merkle 证明面板:proof 路径 + root + verified(中性展示)
export function MerkleProofPanel({ refs = [], proof, onLoadProof }) {
  return (
    <section className="rounded-xl border border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
        <h2 className="text-[13px] font-semibold text-ink">Merkle 证明面板(proof 路径 + root)</h2>
        <div className="ml-auto flex items-center gap-1.5">
          {refs.map((i) => (
            <button
              key={i}
              onClick={() => onLoadProof?.(i)}
              className="px-2.5 py-1 rounded-lg border border-line bg-paper text-[11px] text-ink-soft hover:border-vault-300 hover:text-vault-700"
            >
              证明 #{i}
            </button>
          ))}
        </div>
      </div>
      <div className="p-4 space-y-2">
        {!proof && (
          <div className="text-[11px] text-ink-faint">
            (暂无证明数据 — 点击右上「证明 #n」从 GET /api/chain/entry/{'{index}'}/proof 拉取)
          </div>
        )}
        {proof && (
          <>
            <div className="flex items-center gap-2 text-[11px]">
              <span className="mono text-ink-faint">index</span>
              <span className="mono text-ink">#{proof.index}</span>
              <span className="mono text-ink-faint ml-3">leaf</span>
              <span className="mono text-ink break-all flex-1">{proof.leaf}</span>
            </div>
            <div className="text-[11px] font-semibold text-ink-soft">
              proof 路径({(proof.proof || []).length} 步,值来自后端)
            </div>
            {(proof.proof || []).map((p, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px]">
                <Badge color={p.node_left ? 'violet' : 'gray'}>
                  node_left = {String(p.node_left)}
                </Badge>
                <span className="mono text-ink break-all flex-1">{p.sibling}</span>
              </div>
            ))}
            <div className="flex items-center gap-2 text-[11px] pt-1 border-t border-line/70">
              <span className="mono text-ink-faint">root</span>
              <span className="mono text-ink break-all flex-1">{proof.root}</span>
              <CopyButton value={proof.root} />
            </div>
            <Badge color={proof.verified ? 'ok' : 'bad'}>
              {proof.verified ? '证明路径一致' : '证明路径不一致'}
            </Badge>
          </>
        )}
      </div>
    </section>
  )
}

// 四层验证:4 行 layer/ok/detail + 归约徽章(text 取自 detail,后端原样)
export function FourLayerPanel({ verification = [] }) {
  return (
    <section className="rounded-xl border border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
        <h2 className="text-[13px] font-semibold text-ink">四层验证</h2>
        <span className="text-[11px] text-ink-faint">
          输入绑定 / 模型身份 / 响应完整 / 审计日志 · detail 为后端原文
        </span>
      </div>
      <div className="p-4 space-y-2">
        {verification.length === 0 && (
          <div className="text-[11px] text-ink-faint">(无验证层数据)</div>
        )}
        {verification.map((v, i) => (
          <div key={i} className="flex items-start gap-2 flex-wrap rounded-lg border border-line bg-paper px-3 py-2">
            <span className="text-[12px] font-semibold text-ink w-28 shrink-0">{v.layer}</span>
            <Badge color={v.ok === true ? 'ok' : v.ok === false ? 'bad' : 'gray'}>
              {v.ok === true ? '成立' : v.ok === false ? '不成立' : '跳过(不完整)'}
            </Badge>
            <span className="text-[11px] text-ink-soft flex-1 min-w-[180px]">{v.detail}</span>
            <Badge color="violet">归约 · {v.detail}</Badge>
          </div>
        ))}
      </div>
    </section>
  )
}

// reasoning 密文:sealed notice,仅本地展示·不参与多轮回传
export function ReasoningPanel({ message = {} }) {
  const ct = message.reasoning_ct
  const plain = message.reasoning ?? message.reasoning_content ?? message.artifacts?.reasoning
  if (!ct && !plain) {
    return (
      <section className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <h2 className="text-[13px] font-semibold text-ink">reasoning 密文</h2>
        </div>
        <div className="px-4 py-3 text-[11px] text-ink-faint">本条消息无 reasoning 密文。</div>
      </section>
    )
  }
  const ctText = JSON.stringify(ct ?? {}, null, 2)
  return (
    <section className="rounded-xl border border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
        <h2 className="text-[13px] font-semibold text-ink">reasoning 密文</h2>
        <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
          仅本地展示·不参与多轮回传
        </span>
      </div>
      <div className="p-4 space-y-2">
        {plain ? (
          <pre className="max-h-56 overflow-auto mono text-[11px] text-ink bg-paper border border-line rounded-lg p-3 whitespace-pre-wrap break-all">
            {typeof plain === 'string' ? plain : JSON.stringify(plain, null, 2)}
          </pre>
        ) : (
          <>
            <div className="rounded-lg border border-line bg-paper px-3 py-2 text-[11px] text-ink-soft">
              密文封缄(reasoning_ct)不解封 —— sealed blob 仅本地留存,标注同上:仅本地展示·不参与多轮回传。
            </div>
            <pre className="max-h-56 overflow-auto mono text-[11px] text-ink bg-paper border border-line rounded-lg p-3 whitespace-pre-wrap break-all">
              {ctText}
            </pre>
            <CopyButton value={ctText} />
          </>
        )}
      </div>
    </section>
  )
}

// 审计视角容器:链/证明缺省时自动拉取;复算经 POST /api/verify/preimage(纯数据回传)
export default function AuditView({
  message = {},
  artifacts = {},
  verification = [],
  chainEntries = [],
  chain,
  proof: proofProp,
  preimageResult: preimageProp,
}) {
  const refs = message.chain_refs || []
  const [chainData, setChainData] = useState(chain || null)
  const [proof, setProof] = useState(proofProp || null)
  const [preimageResult, setPreimageResult] = useState(preimageProp || null)
  const [recomputeError, setRecomputeError] = useState(null)

  // 缺省数据自动拉取(测试注入 props 时跳过)
  useEffect(() => {
    let alive = true
    if (!chainData && refs.length) {
      api
        .chainStatus()
        .then((r) => alive && setChainData(r.chain || []))
        .catch(() => {})
    }
    if (!proof && refs.length) {
      api
        .chainEntryProof(refs[0])
        .then((p) => alive && setProof(p))
        .catch(() => {})
    }
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [message.id])

  const entriesAll = (chainData && chainData.length ? chainData : chainEntries) || []
  const missing = refs.filter((i) => !entriesAll.some((e) => e.index === i))
  const failing = verification.filter((v) => v.ok === false)

  // 链窗口:chain_refs 前后各 3 条(全链数据可用时)
  let windowEntries = entriesAll
  if (chainData && chainData.length && refs.length) {
    const lo = Math.min(...refs) - 3
    const hi = Math.max(...refs) + 3
    windowEntries = chainData.filter((e) => e.index >= lo && e.index <= hi)
  }

  const outbound = artifacts.outbound || {}
  const preimageRaw = artifacts.canonical_preimage ?? outbound.canonical_preimage ?? ''
  let preimageObj = preimageRaw
  if (typeof preimageRaw === 'string' && preimageRaw) {
    try {
      preimageObj = JSON.parse(preimageRaw)
    } catch {
      preimageObj = preimageRaw // 解析失败按原文展示,复算禁用
    }
  }
  const expectedHash = outbound.input_hash || ''

  const runRecompute = async () => {
    setRecomputeError(null)
    try {
      const res = await api.verifyPreimage(
        typeof preimageObj === 'string' ? JSON.parse(preimageObj) : preimageObj,
        expectedHash,
      )
      setPreimageResult(res)
    } catch (e) {
      setRecomputeError(String(e?.message || e))
    }
  }

  return (
    <div className="space-y-5">
      <PipelineTimeline artifacts={artifacts} message={message} />

      <section className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <h2 className="text-[13px] font-semibold text-ink">哈希链定位(chain_refs 窗口)</h2>
          <Badge color="vault">🛡 审计签名</Badge>
          <span className="ml-auto text-[11px] text-ink-faint">
            消息 ↔ 链双向跳转:条目可跳消息,高亮即本消息
          </span>
        </div>
        <div className="p-4">
          {missing.length > 0 && (
            <div className="mb-3">
              <ChainEntryMissingState missing={missing} />
            </div>
          )}
          <ChainWindow refs={refs} entries={windowEntries} messageId={message.id} />
        </div>
      </section>

      <MerkleProofPanel
        refs={refs}
        proof={proof}
        onLoadProof={(i) => {
          api
            .chainEntryProof(i)
            .then(setProof)
            .catch(() => {})
        }}
      />

      <RecomputePanel
        preimage={preimageObj}
        expectedHash={expectedHash}
        result={preimageResult}
        onRecompute={runRecompute}
        error={recomputeError}
      />

      {failing.length > 0 && <VerificationFailedState layers={failing} />}
      <FourLayerPanel verification={verification} />
      <ReasoningPanel message={message} />
    </div>
  )
}
