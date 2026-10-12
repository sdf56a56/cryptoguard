import { CopyButton } from '../components/ui.jsx'

// 独立复算面板(spec §4.2 R8):canonical preimage + 三值中性比对
// 措辞铁律(验收③):只呈现 两值一致/两值不一致,不下「验证结论」;明示以独立工具复算为准。
export default function RecomputePanel({ preimage, expectedHash, result, onRecompute, error }) {
  const preimageText =
    typeof preimage === 'string' ? preimage : JSON.stringify(preimage ?? {}, null, 2)
  const material = JSON.stringify(
    { preimage: preimage ?? {}, expected_hash: expectedHash ?? '' },
    null,
    2,
  )
  const verdict = result ? (result.match ? '两值一致' : '两值不一致') : '(待复算)'

  return (
    <section className="rounded-xl border border-line bg-surface">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
        <h2 className="text-[13px] font-semibold text-ink">独立复算面板</h2>
        <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
          🔗 抗第二原像 · 可复算
        </span>
        <span className="ml-auto text-[11px] text-ink-faint">以独立工具复算为准</span>
      </div>
      <div className="p-4 space-y-3">
        {/* canonical preimage 全文 */}
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-ink-faint">
              canonical_preimage(后端返回,前端不生成)
            </span>
            <CopyButton value={preimageText} className="ml-auto" />
          </div>
          <pre className="mt-1 max-h-56 overflow-auto mono text-[11px] text-ink bg-paper border border-line rounded-lg p-3 whitespace-pre-wrap break-all">
            {preimageText || '(无)'}
          </pre>
        </div>

        {/* 三值并列:expected_hash / recomputed_hash / match */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <div className="rounded-lg border border-line bg-paper px-3 py-2">
            <div className="mono text-[10px] text-ink-faint">expected_hash</div>
            <div className="mono text-[11px] text-ink break-all mt-1">{expectedHash || '(无)'}</div>
          </div>
          <div className="rounded-lg border border-line bg-paper px-3 py-2">
            <div className="mono text-[10px] text-ink-faint">recomputed_hash</div>
            <div className="mono text-[11px] text-ink break-all mt-1">
              {result ? result.recomputed_hash : '—'}
            </div>
          </div>
          <div
            className={`rounded-lg border px-3 py-2 ${
              result
                ? result.match
                  ? 'border-ok/40 bg-ok-soft'
                  : 'border-bad/40 bg-bad-soft'
                : 'border-line bg-paper'
            }`}
          >
            <div className="mono text-[10px] text-ink-faint">match</div>
            <div
              className={`text-[12px] font-semibold mt-1 ${
                result ? (result.match ? 'text-ok' : 'text-bad') : 'text-ink-faint'
              }`}
            >
              {verdict}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onRecompute}
            className="px-3.5 py-2 rounded-lg bg-vault-500 text-white text-[12px] font-semibold hover:bg-vault-600 active:scale-[0.98] transition-all"
          >
            ▶ 独立复算(POST /api/verify/preimage)
          </button>
          <CopyButton value={material} label="复制复算材料" />
          <span className="text-[10px] text-ink-faint">
            以上仅为两值数据比对展示,以独立工具复算为准(服务端只回数据,不下结论)。
          </span>
        </div>
        {error && (
          <div className="rounded-lg border border-bad/40 bg-bad-soft px-3 py-2 text-[11px] text-bad">
            复算请求失败:{error}
          </div>
        )}
      </div>
    </section>
  )
}
