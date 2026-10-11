import { motion } from 'framer-motion'
import { PageHeader, Card, Badge } from '../components/ui'
import QueryRunner from '../components/QueryRunner'
import { useStore } from '../store'

const STEP_ICONS = {
  '敏感实体检测': '✂️',
  'AES-GCM 加密映射表': '🔐',
  'CP-ABE 策略加密': '🔑',
  'SSE 密文索引': '🔍',
  'ZKP 合规证明': '🧮',
  '生成 nonce/input_hash': '🔗',
  '出站调用 Mock LLM': '📡',
  '解密映射表并还原': '🔓',
  '写入哈希链 + Merkle': '🌲',
}

const BAR_COLORS = ['#4361ee', '#7048e8', '#0d9488', '#0ca678', '#e8890c', '#e03131', '#3b82f6', '#8b5cf6', '#14b8a6']

export default function Pipeline() {
  const { lastResult, running } = useStore()
  const steps = lastResult?.pipeline || []
  const total = lastResult?.total_ms

  return (
    <div>
      <PageHeader icon="🔐" title="密码流水线" subtitle="出站前完成脱敏 + 加密 + 增强 + 四层协议，全程可视化每一步密码学操作与耗时" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <QueryRunner />

        {running && (
          <div className="text-center py-12">
            <div className="inline-block h-10 w-10 border-[3px] border-vault-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-ink-soft mt-4 text-sm">正在执行密码流水线…</p>
          </div>
        )}

        {!running && steps.length > 0 && (
          <Card
            title={`流水线步骤`}
            icon="⚙️"
            accent="vault"
            right={<Badge color="ok">端到端 {total} ms</Badge>}
          >
            <div className="relative pl-7">
              {/* 竖线 */}
              <div className="absolute left-[9px] top-2 bottom-2 w-[2px] bg-gradient-to-b from-vault-500 via-vault-200 to-ok/40 rounded-full" />
              {steps.map((s, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -14 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.07 }}
                  className="relative pb-5 last:pb-0"
                >
                  <span className="absolute left-[-22px] top-1.5 h-[18px] w-[18px] rounded-full bg-white border-2 border-vault-500 flex items-center justify-center">
                    <span className="h-1.5 w-1.5 rounded-full bg-vault-500" />
                  </span>
                  <div className="flex items-center gap-2.5">
                    <span className="text-base">{STEP_ICONS[s.step] || '•'}</span>
                    <span className="text-[13px] text-ink font-medium flex-1">{s.step}</span>
                    <span className="mono text-[11px] px-2 py-0.5 rounded-full bg-vault-50 text-vault-700 border border-vault-100">{s.duration_ms} ms</span>
                  </div>
                  {s.entity_count != null && (
                    <div className="ml-8 mt-1 text-[11px] text-ink-faint">识别到 <span className="text-ink font-medium">{s.entity_count}</span> 个敏感实体</div>
                  )}
                  {s.enabled != null && (
                    <div className="ml-8 mt-1 text-[11px] text-ink-faint">
                      CP-ABE：{s.enabled ? <span className="text-ok">已执行策略加密</span> : '未启用'}
                    </div>
                  )}
                  {s.valid != null && (
                    <div className="ml-8 mt-1 text-[11px] text-ink-faint">
                      ZKP：{s.valid ? <span className="text-ok">证明验证通过</span> : <span className="text-bad">验证失败</span>}
                    </div>
                  )}
                </motion.div>
              ))}
            </div>

            {/* 耗时占比 */}
            <div className="mt-6 pt-4 border-t border-line">
              <div className="text-[11px] text-ink-faint mb-2">各步骤耗时占比</div>
              <div className="flex h-2.5 rounded-full overflow-hidden bg-paper gap-[2px]">
                {steps.map((s, i) => (
                  <div
                    key={i}
                    title={`${s.step}: ${s.duration_ms}ms`}
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${Math.max((s.duration_ms / total) * 100, 0.8)}%`,
                      backgroundColor: BAR_COLORS[i % BAR_COLORS.length],
                    }}
                  />
                ))}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2">
                {steps.map((s, i) => (
                  <div key={i} className="flex items-center gap-1 text-[9px] text-ink-faint">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: BAR_COLORS[i % BAR_COLORS.length] }} />
                    {s.step}
                  </div>
                ))}
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
