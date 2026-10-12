import { useState } from 'react'
import { api } from '../api.js'
import { ACCEPTANCE_ROWS } from './acceptanceRows.js'
import { AcceptanceResult } from './AcceptanceResults.jsx'

// 验收清单抽屉(spec §6.3,复用 AppendixDrawer 模式):
// 每行 = 验收项 | 达标线 | 实测值 | ▶运行按钮 —— run 走 /api/acceptance/*,
// jump 定位现有 Console 区块(锚点滚动 + 高亮,零重写 Console 内部)。
export default function AcceptanceDrawer({ open, onClose }) {
  const [results, setResults] = useState({}) // rowId → {status, data|error}
  const [busy, setBusy] = useState(null)

  // 跳转现有 Console 区块:锚点优先(data-cg-target 暴露时),否则定位控制台整体 + 闪烁高亮
  const jump = (row) => {
    if (typeof document === 'undefined') return
    const el =
      document.querySelector(`[data-cg-target="${row.action.jumpTo}"]`) ||
      document.getElementById('demo-console')
    if (!el) return
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    el.classList.remove('cg-flash')
    void el.offsetWidth // 重启动画
    el.classList.add('cg-flash')
  }

  const run = async (row, degradeKind) => {
    setBusy(row.id)
    setResults((r) => ({ ...r, [row.id]: { status: 'running' } }))
    try {
      const data = await api.acceptanceRun(row.action.apiKind, degradeKind)
      setResults((r) => ({ ...r, [row.id]: { status: 'ok', data } }))
    } catch (e) {
      setResults((r) => ({ ...r, [row.id]: { status: 'error', error: String(e?.message || e) } }))
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 bg-ink/20 z-40"
          onClick={onClose}
          aria-label="关闭验收清单抽屉"
        />
      )}
      <aside
        className={`fixed right-0 top-0 h-screen w-[520px] max-w-[94vw] bg-surface border-l border-line z-50 shadow-lift flex flex-col transition-transform duration-200 ${
          open ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        <div className="flex items-center gap-2 px-5 py-4 border-b border-line">
          <h2 className="display font-bold text-ink text-[15px]">验收清单</h2>
          <span className="text-[11px] text-ink-faint">spec §6.3 · 评委逐条可点</span>
          <button
            onClick={onClose}
            className="ml-auto px-2.5 py-1 rounded-lg border border-line text-ink-soft text-[12px] hover:border-vault-300 hover:text-vault-700"
          >
            关闭 ✕
          </button>
        </div>

        {/* 列头:验收项 | 达标线 | 实测值 | 运行 */}
        <div className="grid grid-cols-[1fr_1fr_1.2fr_auto] gap-2 px-5 py-2 border-b border-line text-[10px] font-semibold text-ink-faint">
          <span>验收项</span>
          <span>达标线</span>
          <span>实测值</span>
          <span>运行</span>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
          {ACCEPTANCE_ROWS.map((row) => (
            <div
              key={row.id}
              data-acceptance-row={row.id}
              className="rounded-xl border border-line bg-paper p-3"
            >
              <div className="flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <div className="text-[12px] font-semibold text-ink">{row.item}</div>
                  <div className="text-[11px] text-ink-soft mt-0.5">达标线:{row.target}</div>
                  {row.hint && (
                    <div className="text-[10px] text-ink-faint mt-0.5">定位:{row.hint}</div>
                  )}
                </div>
                <div className="flex flex-col gap-1 shrink-0">
                  {row.buttons.map((b) => (
                    <button
                      key={b.key}
                      data-acceptance-btn={row.id}
                      data-degrade-kind={b.degradeKind}
                      disabled={busy === row.id}
                      onClick={() =>
                        row.action.type === 'jump' ? jump(row) : run(row, b.degradeKind)
                      }
                      className={`px-2.5 py-1.5 rounded-lg text-[11px] font-semibold transition-all active:scale-[0.98] disabled:opacity-50 ${
                        row.action.type === 'run'
                          ? 'bg-vault-500 text-white hover:bg-vault-600'
                          : 'border border-line bg-surface text-ink-soft hover:border-vault-300 hover:text-vault-700'
                      }`}
                    >
                      {b.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="mt-2 pt-2 border-t border-line/70">
                <div className="text-[10px] text-ink-faint mb-1">实测值</div>
                {results[row.id] ? (
                  <AcceptanceResult rowId={row.id} result={results[row.id]} />
                ) : (
                  <span className="text-[11px] text-ink-faint">
                    {row.action.type === 'run'
                      ? '—(未运行,点右侧按钮取真结果)'
                      : '—(现场演示项,点右侧按钮定位 Console 区块)'}
                  </span>
                )}
              </div>
            </div>
          ))}

          <div className="rounded-lg border border-warn/30 bg-warn-soft/50 px-3 py-2 text-[10px] text-warn">
            诚实边界(如实标注,不造数):回答质量双盲评仍为人工项「未执行」;ProVerif
            待装实跑,形式化结论以落盘预期为准。
          </div>
        </div>
      </aside>
    </>
  )
}
