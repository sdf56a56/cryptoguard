import { PageHeader, Card, Badge, PrimaryButton } from '../components/ui'
import QueryRunner from '../components/QueryRunner'
import { useStore } from '../store'

// Wireshark 风格的出站报文展示（浅色账本风）
export default function Outbound() {
  const { lastResult } = useStore()

  const packets = lastResult
    ? [
        { layer: '应用层 · 出站请求', tone: 'vault', fields: [
          ['prompt_redacted', lastResult.redacted_input],
          ['input_hash', lastResult.input_hash],
          ['nonce', lastResult.nonce],
          ['timestamp', lastResult.timestamp],
        ]},
        { layer: '传输层 · 模型元数据', tone: 'violet', fields: [
          ['model_cert.signature', lastResult.model_cert?.signature?.slice(0, 48) + '…'],
          ['model_id', lastResult.model_cert?.model_id],
          ['auditor_public_key', lastResult.model_cert?.auditor_public_key?.slice(0, 48) + '…'],
        ]},
      ]
    : []

  return (
    <div>
      <PageHeader icon="📡" title="出站请求" subtitle="抓包视角：出站报文只含脱敏内容、哈希、nonce、签名 —— 不含任何明文" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <QueryRunner />

        {lastResult ? (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <Badge color="ok" icon="●">已抓取出站报文</Badge>
              <span className="text-xs text-ink-faint">敏感明文已全部替换，出站泄露面为零</span>
            </div>

            {/* 抓包工具条 */}
            <div className="rounded-xl overflow-hidden border border-line bg-surface shadow-card">
              <div className="flex items-center gap-3 px-4 py-2.5 bg-paper border-b border-line">
                <div className="flex gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-bad/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-warn/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-ok/70" />
                </div>
                <span className="text-[11px] text-ink-soft mono">CryptoGuard Packet Capture — outbound · 代理 → 大模型</span>
              </div>
              {packets.map((p) => (
                <div key={p.layer} className="border-b border-line/70 last:border-0">
                  <div className={`px-4 py-2 text-[11px] font-semibold mono ${
                    p.tone === 'vault' ? 'text-vault-700 bg-vault-50/70' : 'text-crypto-violet bg-crypto-violetSoft/50'
                  }`}>▼ {p.layer}</div>
                  <div className="px-4 py-2.5 space-y-1.5">
                    {p.fields.map(([k, v]) => (
                      <div key={k} className="flex gap-3 text-[11px]">
                        <span className="text-ink-faint mono w-44 shrink-0">{k}</span>
                        <span className="mono text-ink break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <Card title="泄露面检查" icon="🔍" accent="ok">
              <div className="space-y-2">
                {[
                  ['原始敏感字段', '已全部替换为占位符 / 掩码 / 哈希'],
                  ['映射表明文', '已 AES-256-GCM 加密，密文不出本地'],
                  ['非对称密钥', '公钥可公开，私钥不出本地'],
                ].map(([k, v]) => (
                  <div key={k} className="flex items-center gap-3 text-[13px]">
                    <span className="h-5 w-5 rounded-full bg-ok text-white flex items-center justify-center text-[11px] font-bold">✓</span>
                    <span className="text-ink w-32">{k}</span>
                    <span className="text-ink-faint text-xs">{v}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        ) : (
          <div className="text-center text-ink-faint text-sm py-14">
            <div className="text-3xl mb-2">📡</div>
            执行查询后在此查看出站报文抓取结果
          </div>
        )}
      </div>
    </div>
  )
}
