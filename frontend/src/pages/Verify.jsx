import { motion } from 'framer-motion'
import { PageHeader, Card, HashLine, Stamp } from '../components/ui'
import QueryRunner from '../components/QueryRunner'
import { useStore } from '../store'

export default function Verify() {
  const { lastResult, running } = useStore()
  const verified = lastResult?.status === 'verified'

  return (
    <div>
      <PageHeader icon="✓" title="响应验证" subtitle="回程四层验证逐项打勾：输入绑定 → 模型身份 → 响应完整 → 可审计" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <QueryRunner />

        {running && (
          <div className="text-center py-12">
            <div className="inline-block h-10 w-10 border-[3px] border-vault-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-ink-soft mt-4 text-sm">回程验证中…</p>
          </div>
        )}

        {!running && lastResult && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <Stamp ok={verified} label={verified ? '四层验证通过' : '验证失败'} />
              <span className="text-xs text-ink-faint mono">{lastResult.total_ms} ms · {lastResult.request_id}</span>
            </div>

            <Card title="验证流水线" icon="🛡️" accent={verified ? 'ok' : 'bad'}>
              <div className="space-y-3">
                {lastResult.verification?.map((v, i) => (
                  <motion.div
                    key={v.layer}
                    initial={{ opacity: 0, scale: 0.96 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.15 }}
                    className={`p-3.5 rounded-xl border flex items-center gap-3 ${
                      v.ok ? 'border-ok/30 bg-ok-soft/60' : 'border-bad/40 bg-bad-soft alert-pulse'
                    }`}
                  >
                    <motion.span
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ delay: i * 0.15 + 0.2, type: 'spring', stiffness: 300 }}
                      className={`h-9 w-9 rounded-full text-white flex items-center justify-center text-lg font-bold shadow-card ${v.ok ? 'bg-ok' : 'bg-bad'}`}
                    >
                      {v.ok ? '✓' : '✗'}
                    </motion.span>
                    <div>
                      <div className="text-[13px] font-semibold text-ink">第 {i + 1} 层 · {v.layer}</div>
                      <div className="text-[11px] text-ink-soft mt-0.5">{v.detail}</div>
                    </div>
                    <span className="ml-auto mono text-[9px] text-ink-faint">
                      {['BIND', 'CERT', 'SIGN', 'AUDIT'][i]}
                    </span>
                  </motion.div>
                ))}
              </div>
            </Card>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card title="验证通过的密码字段" icon="🔐" accent="vault">
                <div className="receipt p-3">
                  <HashLine label="input_hash" value={lastResult.input_hash} />
                  <HashLine label="nonce" value={lastResult.nonce} />
                  <HashLine label="response_hash" value={lastResult.response_hash} />
                  <HashLine label="signature" value={lastResult.signature} />
                </div>
              </Card>
              <Card title="还原明文（本地解密映射表）" icon="🔓" accent="ok">
                <p className="text-[13px] text-ink leading-relaxed">{lastResult.restored_output}</p>
              </Card>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
