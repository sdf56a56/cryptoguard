import { useStore } from '../store'
import { Badge, Card, HashLine, Stamp } from './ui'
import { motion } from 'framer-motion'

// 结果摘要：流水线执行结果概览，供多页面复用
export default function ResultSummary() {
  const { lastResult, running } = useStore()

  if (!lastResult && !running) {
    return (
      <div className="text-center text-ink-faint text-sm py-14">
        <div className="text-3xl mb-2">📭</div>
        尚未执行查询，请在上方输入明文并点击「执行安全查询」
      </div>
    )
  }
  if (running || !lastResult) {
    return (
      <div className="text-center py-14">
        <div className="inline-block h-8 w-8 border-[3px] border-vault-500 border-t-transparent rounded-full animate-spin" />
        <div className="text-ink-soft text-sm mt-3">密码流水线执行中…</div>
      </div>
    )
  }

  const r = lastResult
  const verified = r.status === 'verified'

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="flex items-center gap-3">
        <Stamp ok={verified} label={verified ? '验证通过' : '验证失败'} />
        {r.attack && <Badge color="bad" pulse>攻击：{r.attack}</Badge>}
        {r.abe_enabled && <Badge color="violet">CP-ABE 已启用</Badge>}
        <span className="ml-auto text-xs text-ink-faint mono">端到端 {r.total_ms} ms · {r.entities?.length || 0} 个敏感实体</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="脱敏前（本地明文）" icon="📄" accent="warn">
          <p className="text-xs text-ink leading-relaxed">
            {r.original_input || r.redacted_input}
          </p>
        </Card>
        <Card title="出站（仅脱敏内容）" icon="📡" accent="vault">
          <p className="text-xs text-ink leading-relaxed mono">{r.redacted_input}</p>
        </Card>
        <Card title="模型输出" icon="🤖" accent="violet">
          <p className="text-xs text-ink leading-relaxed">{r.model_output}</p>
        </Card>
      </div>

      <Card title="四层验证结果" icon="✓" accent={verified ? 'ok' : 'bad'}>
        <div className="space-y-2">
          {r.verification?.map((v) => (
            <div key={v.layer} className="flex items-center gap-3 text-sm">
              <span className={`h-5 w-5 rounded-full flex items-center justify-center text-white text-[11px] font-bold ${v.ok ? 'bg-ok' : 'bg-bad'}`}>{v.ok ? '✓' : '✗'}</span>
              <span className="text-ink w-32 shrink-0">{v.layer}</span>
              <span className="text-xs text-ink-faint">{v.detail}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card title="密码学字段（Receipt）" icon="🔐" accent="vault">
        <div className="receipt p-3">
          <HashLine label="input_hash" value={r.input_hash} />
          <HashLine label="nonce" value={r.nonce} />
          <HashLine label="response_hash" value={r.response_hash} />
          <HashLine label="signature" value={r.signature} />
          <HashLine label="timestamp" value={r.timestamp} />
        </div>
      </Card>
    </motion.div>
  )
}
