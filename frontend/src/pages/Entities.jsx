import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { PageHeader, Card, Badge, PrimaryButton } from '../components/ui'
import { api } from '../api'
import { useStore } from '../store'

const SENS_COLOR = {
  high: { zh: '高敏感', color: 'bad' },
  medium: { zh: '中敏感', color: 'warn' },
  low: { zh: '低敏感', color: 'gray' },
}

const MODES = [
  {
    key: 'placeholder',
    label: '占位符替换',
    example: '患者 [NAME_1] 手机 [PHONE_1]',
    desc: '语义保留最完整，大模型理解上下文最佳；映射表本地 AES-GCM 加密保管，可逆还原。',
    icon: '🏷️',
  },
  {
    key: 'mask',
    label: '掩码打码',
    example: '患者 张* 手机 13*******00',
    desc: '保留首尾字符便于人工核对；可读性折中，适合展示与导出场景。',
    icon: '🎭',
  },
  {
    key: 'hash',
    label: '哈希替换',
    example: '患者 sha256:a3a0bafd…',
    desc: '确定性哈希，同一明文映射同一哈希，支持统计关联；不可逆（本地另存映射用于还原）。',
    icon: '#️⃣',
  },
]

export default function Entities() {
  const { policy, setPolicy } = useStore()
  const [types, setTypes] = useState([])
  const [mode, setMode] = useState('placeholder')
  const [enabled, setEnabled] = useState(new Set())
  const [saved, setSaved] = useState(false)
  const [testing, setTesting] = useState(null)

  useEffect(() => {
    api.entities().then((r) => {
      setTypes(r.types)
      setMode(r.policy.mode)
      setEnabled(new Set(r.policy.enabled_types))
      setPolicy(r.policy)
    })
  }, [])

  function toggle(t) {
    const next = new Set(enabled)
    next.has(t) ? next.delete(t) : next.add(t)
    setEnabled(next)
    setSaved(false)
  }

  async function save() {
    const p = await api.setPolicy(mode, [...enabled])
    setPolicy(p)
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  async function tryMode(m) {
    setMode(m)
    setSaved(false)
    setTesting(m)
    setTimeout(() => setTesting(null), 500)
  }

  const example = '患者张伟手机13800138000'
  const exampleMap = {
    placeholder: '患者 [NAME_1] 手机 [PHONE_1]',
    mask: '患者 张* 手机 13*******00',
    hash: '患者 sha256:a3a0bafd… 手机 sha256:a6942f97…',
  }

  return (
    <div>
      <PageHeader
        icon="🗂️"
        title="实体与策略"
        subtitle="配置敏感实体类型与脱敏模式 —— 对标 Presidio 识别器目录 + 匿名化算子"
        badge={<Badge color={saved ? 'ok' : 'vault'}>{saved ? '✓ 策略已保存' : `${enabled.size} / ${types.length} 类已启用`}</Badge>}
      />
      <div className="px-8 py-6 max-w-6xl space-y-5">
        {/* 脱敏模式选择 */}
        <Card title="脱敏模式（Anonymizer Operator）" icon="⚙️" accent="vault">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {MODES.map((m) => (
              <motion.button
                key={m.key}
                onClick={() => tryMode(m.key)}
                whileTap={{ scale: 0.98 }}
                className={`text-left p-4 rounded-xl border-2 transition-all ${
                  mode === m.key
                    ? 'border-vault-500 bg-vault-50 shadow-card'
                    : 'border-line bg-surface hover:border-vault-200'
                }`}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="text-lg">{m.icon}</span>
                  <span className="text-[13px] font-semibold text-ink">{m.label}</span>
                  {mode === m.key && <Badge color="vault">使用中</Badge>}
                </div>
                <div className="mono text-[10px] text-vault-700 bg-white rounded px-2 py-1 border border-vault-100 mb-1.5">
                  {m.example}
                </div>
                <p className="text-[11px] text-ink-soft leading-snug">{m.desc}</p>
              </motion.button>
            ))}
          </div>
          <div className="mt-3 p-3 rounded-lg bg-paper border border-line">
            <div className="text-[11px] text-ink-faint mb-1">脱敏效果预览</div>
            <div className="mono text-[12px] text-ink">{example} → <span className="text-vault-700 font-medium">{exampleMap[mode]}</span></div>
          </div>
        </Card>

        {/* 实体类型目录 */}
        <Card
          title="敏感实体类型目录（Recognizer Catalog）"
          icon="🏷️"
          accent="violet"
          right={<GhostToggle enabled={enabled} types={types} setEnabled={(s) => { setEnabled(s); setSaved(false) }} />}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {types.map((t) => {
              const s = SENS_COLOR[t.sensitivity] || SENS_COLOR.medium
              const on = enabled.has(t.type)
              return (
                <motion.div
                  key={t.type}
                  layout
                  className={`p-3 rounded-xl border transition-all ${
                    on ? 'border-vault-200 bg-white shadow-card' : 'border-line bg-paper opacity-60'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggle(t.type)}
                      className={`w-8 h-[18px] rounded-full transition-colors relative ${on ? 'bg-vault-500' : 'bg-line-strong'}`}
                      aria-label={`toggle ${t.type}`}
                    >
                      <motion.span
                        layout
                        className={`absolute top-[2px] h-[14px] w-[14px] rounded-full bg-white shadow ${on ? 'left-[16px]' : 'left-[2px]'}`}
                      />
                    </button>
                    <span className="text-[12px] font-semibold text-ink">{t.zh}</span>
                    <span className="mono text-[10px] text-ink-faint">{t.type}</span>
                    <Badge color={s.color} >{s.zh}</Badge>
                  </div>
                  <div className="mt-2 flex items-center gap-1.5">
                    <span className="mono text-[9px] px-1.5 py-0.5 rounded bg-paper border border-line text-ink-soft">{t.prefix}_*</span>
                    <span className="text-[10px] text-ink-faint">识别方式：{t.method}</span>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </Card>

        {/* 保存 */}
        <div className="flex items-center gap-3">
          <PrimaryButton onClick={save} icon="💾">保存策略</PrimaryButton>
          <span className="text-xs text-ink-faint">
            策略实时生效于「安全对话」「输入脱敏」「密码流水线」等所有链路
          </span>
          {saved && (
            <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-xs text-ok font-medium">已同步到代理</motion.span>
          )}
        </div>
      </div>
    </div>
  )
}

function GhostToggle({ enabled, types, setEnabled }) {
  const all = types.length > 0 && enabled.size === types.length
  return (
    <button
      onClick={() => setEnabled(all ? new Set() : new Set(types.map((t) => t.type)))}
      className="text-[11px] px-2.5 py-1 rounded-lg border border-line text-ink-soft hover:border-vault-300 hover:text-vault-700 transition-colors"
    >
      {all ? '全部关闭' : '全部启用'}
    </button>
  )
}
