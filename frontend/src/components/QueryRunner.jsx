import { useState } from 'react'
import { api } from '../api'
import { useStore, SCENARIOS } from '../store'
import { Card, PrimaryButton } from './ui'

// 攻击注入按钮定义
export const ATTACKS = [
  { key: 'tamper', label: '篡改响应', icon: '🔀', desc: '中间人篡改输出 → 哈希/签名验证失败' },
  { key: 'replay', label: '重放旧响应', icon: '♻️', desc: '复用旧 nonce → 防重放检测失败' },
  { key: 'forge_cert', label: '伪造模型声明', icon: '🎭', desc: '伪造 model_cert → 审计签名失败' },
  { key: 'tamper_log', label: '篡改日志', icon: '📝', desc: '改动日志 → Merkle 证明失败' },
  { key: 'repudiate', label: '用户诬告', icon: '🤥', desc: 'input_hash 绑定 → 诬告不成立' },
]

export default function QueryRunner({ autoSubmit = false, showInput = true }) {
  const { setLastResult, scenario, setScenario, running, setRunning } = useStore()
  const [text, setText] = useState(SCENARIOS[scenario].sample)
  const [attack, setAttack] = useState(null)
  const [enableABE, setEnableABE] = useState(true)

  async function run(attackKey = null) {
    setRunning(true)
    setAttack(attackKey)
    try {
      const payload = {
        text,
        scenario,
        attack: attackKey,
        attributes: enableABE ? SCENARIOS[scenario].attributes : null,
      }
      const result = await api.query(payload)
      setLastResult(result)
    } catch (e) {
      console.error(e)
    } finally {
      setRunning(false)
    }
  }

  function switchScenario(s) {
    setScenario(s)
    setText(SCENARIOS[s].sample)
    setLastResult(null)
    setAttack(null)
  }

  return (
    <div className="space-y-4">
      {showInput && (
        <Card title="明文输入（仅存本地）" icon="⌨️" accent="vault">
          <div className="flex items-center gap-2 mb-3">
            {Object.entries(SCENARIOS).map(([k, v]) => (
              <button
                key={k}
                onClick={() => switchScenario(k)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  scenario === k
                    ? 'bg-vault-500 text-white shadow-[0_2px_8px_-2px_rgba(67,97,238,0.5)]'
                    : 'bg-paper border border-line text-ink-soft hover:border-vault-300'
                }`}
              >
                {v.label}
              </button>
            ))}
            <div className="ml-auto">
              <label className="flex items-center gap-1.5 text-xs text-ink-soft cursor-pointer select-none">
                <input type="checkbox" checked={enableABE} onChange={(e) => setEnableABE(e.target.checked)} className="accent-vault-500" />
                启用 CP-ABE 细粒度授权
              </label>
            </div>
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={4}
            className="w-full rounded-lg bg-paper border border-line focus:border-vault-400 focus:ring-2 focus:ring-vault-100 outline-none p-3 text-[13px] text-ink resize-y transition-all"
            placeholder="输入包含敏感信息的明文..."
          />
          <div className="flex items-center gap-3 mt-3">
            <PrimaryButton onClick={() => run(null)} disabled={running} icon="▶">
              {running ? '处理中…' : '执行安全查询'}
            </PrimaryButton>
            <span className="text-xs text-ink-faint">出站前将完成脱敏 + 加密 + 四层可验证协议</span>
          </div>
        </Card>
      )}

      {!autoSubmit && (
        <Card title="攻击注入" icon="⚠️" accent="bad">
          <p className="text-xs text-ink-faint mb-3">选择一种攻击方式重新执行查询，观察验证失败告警</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            {ATTACKS.map((a) => (
              <button
                key={a.key}
                onClick={() => run(a.key)}
                disabled={running}
                className="group text-left p-3 rounded-xl bg-paper border border-line hover:border-bad/50 hover:bg-bad-soft/50 transition-colors disabled:opacity-50"
              >
                <div className="text-lg mb-1">{a.icon}</div>
                <div className="text-xs font-semibold text-ink">{a.label}</div>
                <div className="text-[10px] text-ink-faint mt-1 leading-snug">{a.desc}</div>
              </button>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
