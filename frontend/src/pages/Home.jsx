import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { PageHeader, Card, Badge, PrimaryButton, GhostButton } from '../components/ui'
import { api } from '../api'

const THREATS = [
  { role: '服务商', ability: '诚实但可审计，可能被入侵，可能事后抵赖', trust: '半可信' },
  { role: '外部攻击者', ability: '完全不可信，可篡改/重放/伪造响应，但无服务商私钥', trust: '不可信' },
  { role: '用户', ability: '可能诬告、伪造输入，但无服务商私钥', trust: '不可信' },
  { role: '第三方审计机构', ability: '可信，签名模型声明，不参与每次推理', trust: '可信' },
]

const GOALS = [
  { name: '响应完整性', desc: 'response_hash + 服务商签名，防篡改', icon: '🔒', algo: 'Ed25519' },
  { name: '输入绑定', desc: 'nonce + input_hash，防替换与诬告', icon: '🔗', algo: 'SHA-256' },
  { name: '不可抵赖', desc: 'Ed25519/SM2 签名，事后可追溯', icon: '📌', algo: 'EUF-CMA' },
  { name: '可审计', desc: '哈希链 + Merkle 根，日志防篡改', icon: '📋', algo: 'Merkle' },
  { name: '防重放', desc: 'nonce 一次性校验', icon: '♻️', algo: 'Timestamp' },
]

const NOT_PROMISE = [
  '不证明大模型内部实际计算了什么（非 zkML）',
  '不承诺防服务商主动调包（除非加 TEE）',
  '不承诺防服务商偷懒计算',
]

const LAYERS = [
  { n: 1, name: '输入绑定', formula: 'input_hash = H(脱敏输入) ‖ nonce ‖ ts' },
  { n: 2, name: '模型身份', formula: 'model_cert = Sign(sk_auditor, model_id‖ver‖date‖hash)' },
  { n: 3, name: '响应完整', formula: 'response_hash = H(out‖input_hash‖cert‖nonce‖ts)；sig = Sign(sk_p)' },
  { n: 4, name: '可审计日志', formula: 'log_i = H(req‖resp‖ts‖log_{i-1}) + Merkle root' },
]

export default function Home() {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    api.stats().then(setStats).catch(() => {})
  }, [])

  return (
    <div className="bg-ledger">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-line bg-gradient-to-b from-white via-white to-paper">
        {/* 装饰 */}
        <div className="absolute inset-0 pointer-events-none opacity-[0.5]" style={{
          backgroundImage: 'radial-gradient(circle at 85% 20%, rgba(67,97,238,0.10) 0%, transparent 45%), radial-gradient(circle at 10% 90%, rgba(13,148,136,0.08) 0%, transparent 40%)',
        }} />
        <div className="relative px-10 pt-12 pb-10">
          <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
            <Badge color="vault" icon="◈">密码学竞赛作品 · CG-ABE-SSE 混合可验证隐私代理</Badge>
            <h1 className="display text-[42px] leading-[1.12] font-extrabold text-ink mt-4 max-w-3xl tracking-tight">
              用户与大模型之间，
              <br />
              一道<span className="relative inline-block">
                <span className="relative z-10 text-vault-600">看不见的加密防线</span>
                <motion.span
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.6, delay: 0.4, ease: 'easeOut' }}
                  className="absolute bottom-1 left-0 h-3 w-full bg-vault-100 origin-left -z-0 rounded"
                />
              </span>
            </h1>
            <p className="text-[15px] text-ink-soft mt-4 max-w-2xl leading-relaxed">
              本地代理自动识别敏感信息，脱敏后以占位符送入大模型 —— <strong className="text-ink">明文永不出本地</strong>；
              响应回程经四层可验证机制（输入绑定 · 模型身份 · 响应完整 · 可审计日志）校验，
              验证通过才在本地还原明文。每一层都有明确的安全归约，每一个承诺都做得到。
            </p>
            <div className="flex items-center gap-3 mt-6">
              <Link to="/chat">
                <PrimaryButton icon="💬">体验安全对话</PrimaryButton>
              </Link>
              <Link to="/attack">
                <GhostButton icon="⚠️">查看攻击演示</GhostButton>
              </Link>
              <Link to="/lab">
                <GhostButton icon="🧪">密码实验室</GhostButton>
              </Link>
            </div>
          </motion.div>

          {/* 统计条 */}
          {stats && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25 }}
              className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-8 max-w-2xl"
            >
              {[
                { label: '安全查询次数', value: stats.queries, icon: '🔍' },
                { label: '敏感实体已保护', value: stats.entities_protected, icon: '🛡️' },
                { label: '攻击已拦截', value: stats.attacks_blocked, icon: '🚫' },
                { label: '平均延迟', value: stats.avg_latency_ms + ' ms', icon: '⚡' },
              ].map((s) => (
                <div key={s.label} className="rounded-xl border border-line bg-surface px-4 py-3 shadow-card">
                  <div className="text-[11px] text-ink-faint">{s.icon} {s.label}</div>
                  <div className="display text-xl font-bold text-ink mt-0.5">{s.value}</div>
                </div>
              ))}
            </motion.div>
          )}
        </div>
      </div>

      <div className="px-10 py-8 space-y-6 max-w-6xl">
        {/* 数据流 */}
        <Card title="端到端数据流：明文永远不出本地" icon="→" accent="vault">
          <div className="flex items-stretch gap-2 overflow-x-auto pb-1">
            {[
              { label: '用户明文', sub: '本地', icon: '✍️', tone: 'warn' },
              { label: '敏感检测', sub: '13 类实体', icon: '✂️', tone: 'vault' },
              { label: '脱敏加密', sub: 'AES-256-GCM', icon: '🔐', tone: 'vault' },
              { label: '出站占位符', sub: '[NAME_1]…', icon: '📡', tone: 'vault' },
              { label: '大模型', sub: '只见占位符', icon: '🤖', tone: 'violet' },
              { label: '四层验证', sub: '签名/哈希/nonce', icon: '✓', tone: 'ok' },
              { label: '本地还原', sub: '明文回来', icon: '🔓', tone: 'ok' },
            ].map((s, i) => (
              <motion.div
                key={s.label}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08 }}
                className="flex-1 min-w-[110px]"
              >
                <div className={`h-full rounded-xl border p-3 text-center ${
                  s.tone === 'ok' ? 'border-ok/30 bg-ok-soft/50'
                  : s.tone === 'warn' ? 'border-warn/30 bg-warn-soft/50'
                  : s.tone === 'violet' ? 'border-crypto-violet/30 bg-crypto-violetSoft/50'
                  : 'border-vault-200 bg-vault-50/50'
                }`}>
                  <div className="text-lg">{s.icon}</div>
                  <div className="text-[11px] font-semibold text-ink mt-1">{s.label}</div>
                  <div className="text-[9px] text-ink-faint mono">{s.sub}</div>
                </div>
                {i < 6 && <div className="hidden" />}
              </motion.div>
            ))}
          </div>
        </Card>

        {/* 四层协议 */}
        <Card title="四层可验证协议（每层均有安全归约）" icon="🧩" accent="vault">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {LAYERS.map((l) => (
              <div key={l.n} className="receipt p-3.5">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="h-6 w-6 rounded-full bg-vault-500 text-white flex items-center justify-center text-[11px] font-bold">{l.n}</span>
                  <span className="text-[13px] font-semibold text-ink">{l.name}</span>
                </div>
                <div className="text-[10px] text-ink-soft mono break-all leading-relaxed">{l.formula}</div>
              </div>
            ))}
          </div>
        </Card>

        {/* 三层架构 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {[
            { title: '出站隐私层', items: ['NLP + 正则自动识别敏感信息', 'AES-256-GCM 加密映射表', 'CP-ABE 细粒度授权', 'SSE 密文可搜索'], accent: 'vault', icon: '🔐' },
            { title: '回程验证层', items: ['nonce + input_hash 输入绑定', 'model_cert 模型身份声明', 'response_hash + Ed25519 签名', '防重放 / 防抵赖'], accent: 'ok', icon: '✓' },
            { title: '审计争议层', items: ['SHA-256 哈希链日志', 'Merkle 树 O(log n) 证明', '日志根哈希定期公示', '争议解决流程'], accent: 'violet', icon: '⛓️' },
          ].map((l) => (
            <Card key={l.title} title={l.title} icon={l.icon} accent={l.accent}>
              <ul className="space-y-2">
                {l.items.map((i) => (
                  <li key={i} className="text-[12px] text-ink-soft flex items-start gap-2">
                    <span className="text-vault-500 mt-0.5">▸</span>{i}
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>

        {/* 威胁模型 + 安全目标 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card title="威胁模型 · 角色能力矩阵" icon="🎯" accent="warn">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-ink-faint border-b border-line">
                  <th className="text-left py-2">角色</th>
                  <th className="text-left py-2">能力</th>
                  <th className="text-left py-2">信任</th>
                </tr>
              </thead>
              <tbody>
                {THREATS.map((t) => (
                  <tr key={t.role} className="border-b border-line/60 last:border-0">
                    <td className="py-2.5 text-ink font-medium">{t.role}</td>
                    <td className="py-2.5 text-ink-soft pr-2">{t.ability}</td>
                    <td className="py-2.5">
                      <Badge color={t.trust === '可信' ? 'ok' : t.trust === '半可信' ? 'warn' : 'bad'}>{t.trust}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <div className="space-y-4">
            <Card title="安全目标与密码学依据" icon="🎯" accent="ok">
              <div className="space-y-2">
                {GOALS.map((g) => (
                  <div key={g.name} className="flex items-start gap-2.5 text-sm">
                    <span>{g.icon}</span>
                    <div className="flex-1">
                      <span className="text-ink font-medium text-[12px]">{g.name}</span>
                      <span className="text-ink-soft text-[11px]"> — {g.desc}</span>
                    </div>
                    <span className="mono text-[9px] px-1.5 py-0.5 rounded bg-vault-50 text-vault-700 border border-vault-100 shrink-0">{g.algo}</span>
                  </div>
                ))}
              </div>
            </Card>
            <Card title="明确不承诺（诚实边界）" icon="🚧" accent="bad">
              <ul className="space-y-1.5">
                {NOT_PROMISE.map((n) => (
                  <li key={n} className="text-[12px] text-ink-soft flex items-center gap-2">
                    <span className="text-bad">✗</span>{n}
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}
