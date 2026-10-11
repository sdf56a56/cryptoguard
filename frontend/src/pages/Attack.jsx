import { motion } from 'framer-motion'
import { PageHeader, Card, Badge, Stamp } from '../components/ui'
import QueryRunner, { ATTACKS } from '../components/QueryRunner'
import { useStore } from '../store'

const ATTACK_TALK = {
  tamper: '中间人在传输中篡改模型输出。代理重算 response_hash 发现不一致 → 签名校验失败 → 拒绝输出。',
  replay: '攻击者重放之前捕获的旧响应。代理校验 nonce 发现已被使用 → 判定重放攻击 → 拒绝。',
  forge_cert: '攻击者伪造模型身份声明。代理用审计机构公钥验签 → 失败 → 拒绝信任该模型。',
  tamper_log: '攻击者篡改审计日志条目。Merkle 证明与根哈希不匹配 → 日志完整性校验失败。',
  repudiate: '用户诬告服务商返回错误内容。input_hash 双向绑定，用户声称的输入无法对上 → 诬告不成立。',
}

export default function Attack() {
  const { lastResult, running } = useStore()

  return (
    <div>
      <PageHeader icon="⚠️" title="攻击演示" subtitle="5 种攻击一键注入，观察四层验证如何逐层拦截并告警" />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <QueryRunner />

        {/* 攻击结果告警 */}
        {!running && lastResult && lastResult.attack && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`p-5 rounded-xl border-2 ${
              lastResult.status === 'rejected' ? 'border-bad bg-bad-soft' : 'border-warn bg-warn-soft'
            }`}
          >
            <div className="flex items-center gap-3">
              <Stamp ok={false} label="攻击被拦截" />
              <div>
                <div className="text-[13px] font-bold text-ink">攻击类型：{lastResult.attack}</div>
                <div className="text-[12px] text-ink-soft mt-0.5">{lastResult.attack_result}</div>
              </div>
              <Badge color="bad" pulse>验证失败</Badge>
            </div>
            <p className="text-[11px] text-ink-soft mt-3 leading-relaxed">{ATTACK_TALK[lastResult.attack]}</p>
          </motion.div>
        )}

        {/* 正常结果时的提示 */}
        {!running && lastResult && !lastResult.attack && (
          <div className="p-4 rounded-xl border border-ok/30 bg-ok-soft/60 text-[12px] text-ink-soft">
            ✓ 最近一次为正常查询，四层验证全部通过。点击上方攻击按钮注入攻击，观察验证失败告警。
          </div>
        )}

        {/* 5 种攻击说明 */}
        <Card title="5 种攻击与防御机制对照" icon="🛡️" accent="bad">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {ATTACKS.map((a, i) => (
              <motion.div
                key={a.key}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                className="p-3.5 rounded-xl border border-line bg-paper hover:border-bad/40 hover:bg-bad-soft/40 transition-colors"
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-lg">{a.icon}</span>
                  <span className="text-[12px] font-semibold text-ink">{a.label}</span>
                  <span className="ml-auto mono text-[9px] text-ink-faint">ATT-{i + 1}</span>
                </div>
                <p className="text-[10px] text-ink-faint leading-snug">{a.desc}</p>
              </motion.div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}
