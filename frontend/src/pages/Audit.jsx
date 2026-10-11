import { useEffect, useState } from 'react'
import { PageHeader, Card, Badge, HashLine, GhostButton, PrimaryButton } from '../components/ui'
import { api } from '../api'

export default function Audit() {
  const [data, setData] = useState(null)

  async function load() {
    setData(await api.logs())
  }
  useEffect(() => { load() }, [])

  async function doTamper(index) {
    setData(await api.tamperLog(index))
  }

  const chain = data?.chain || []
  const merkle = data?.merkle

  return (
    <div>
      <PageHeader
        icon="⛓️"
        title="审计日志"
        subtitle="SHA-256 哈希链 + Merkle 树：日志防篡改、可追溯、O(log n) 可证明"
        badge={<Badge color={data?.chain_valid === false ? 'bad' : 'ok'} pulse={data?.chain_valid === false}>
          哈希链：{data?.chain_valid === false ? '已篡改 ✗' : data == null ? '…' : '完整 ✓'}
        </Badge>}
      />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <div className="flex items-center gap-3">
          <GhostButton onClick={load} icon="↻">刷新日志</GhostButton>
          <span className="text-xs text-ink-faint">点击「篡改此条日志」可演示 Merkle 证明如何检测篡改</span>
        </div>

        {/* 哈希链 */}
        <Card title={`哈希链（${chain.length} 条）`} icon="⛓️" accent="vault">
          <div className="space-y-2">
            {chain.length === 0 && (
              <div className="text-sm text-ink-faint text-center py-8">
                <div className="text-3xl mb-2">📭</div>
                暂无日志，请先在「安全对话」或「密码流水线」执行查询
              </div>
            )}
            {chain.map((e) => (
              <div key={e.index} className={`p-3.5 rounded-xl border transition-colors ${
                e.tampered ? 'border-bad/50 bg-bad-soft alert-pulse' : 'border-line bg-paper hover:border-vault-200'
              }`}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-[11px] font-bold text-vault-700 mono">#{e.index}</span>
                  {e.tampered && <Badge color="bad" pulse>已篡改</Badge>}
                  <span className="ml-auto text-[10px] text-ink-faint mono">{e.timestamp}</span>
                </div>
                <div className="receipt p-2.5">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
                    <div className="text-[10px] mono"><span className="text-ink-faint">req_digest:</span> <span className="text-ink">{e.request_digest?.slice(0, 20)}…</span></div>
                    <div className="text-[10px] mono"><span className="text-ink-faint">resp_digest:</span> <span className="text-ink">{e.response_digest?.slice(0, 20)}…</span></div>
                  </div>
                  <div className="text-[10px] mono mt-1">
                    <span className="text-ink-faint">hash:</span> <span className={e.tampered ? 'text-bad' : 'text-vault-700'}>{e.hash?.slice(0, 48)}…</span>
                  </div>
                  <div className="text-[10px] mono mt-0.5">
                    <span className="text-ink-faint">prev:</span> <span className="text-ink-soft">{e.prev_hash?.slice(0, 48)}…</span>
                  </div>
                </div>
                <div className="mt-2">
                  <button
                    onClick={() => doTamper(e.index)}
                    className="text-[10px] px-2.5 py-1 rounded-lg border border-bad/30 text-bad hover:bg-bad-soft transition-colors"
                  >
                    ⚠ 篡改此条日志（演示）
                  </button>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Merkle 树 */}
        <Card title="Merkle 树" icon="🌲" accent="violet">
          {merkle ? (
            <div className="space-y-4">
              <div className="receipt p-3">
                <HashLine label="根哈希 ROOT" value={merkle.root} />
              </div>
              <div>
                <div className="text-[11px] text-ink-faint mb-2">叶子节点（日志哈希）</div>
                <div className="flex flex-wrap gap-1.5">
                  {merkle.leaves.map((l, i) => (
                    <div key={i} className="text-[10px] mono px-2 py-1 rounded-lg border border-line bg-paper text-ink-soft" title={l}>
                      L{i}: {l.slice(0, 12)}…
                    </div>
                  ))}
                </div>
              </div>
              {merkle.levels.length > 2 && (
                <div>
                  <div className="text-[11px] text-ink-faint mb-2">内部层（逐层聚合）</div>
                  <div className="space-y-1.5">
                    {merkle.levels.slice(1, -1).map((level, li) => (
                      <div key={li} className="flex flex-wrap gap-1.5 items-center">
                        <span className="text-[9px] mono text-ink-faint w-10">L{li + 1}</span>
                        {level.map((h, hi) => (
                          <div key={hi} className="text-[10px] mono px-2 py-1 rounded-lg bg-vault-50 text-vault-700 border border-vault-100" title={h}>
                            {h.slice(0, 12)}…
                          </div>
                        ))}
                      </div>
                    ))}
                    <div className="flex items-center gap-1.5 pt-1">
                      <span className="text-[9px] mono text-ink-faint w-10">ROOT</span>
                      <div className="text-[10px] mono px-2 py-1 rounded-lg bg-ok-soft text-ok border border-ok/30 font-semibold">
                        {merkle.root.slice(0, 16)}…
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-ink-faint text-center py-8">暂无数据</div>
          )}
        </Card>
      </div>
    </div>
  )
}
