import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { PageHeader, Card, Badge, PrimaryButton, HashLine } from '../components/ui'
import { api } from '../api'
import { useStore, SCENARIOS } from '../store'

const ENTITY_COLORS = {
  NAME: '#e03131', ID: '#e8890c', CARD: '#e8890c', PHONE: '#e03131',
  EMAIL: '#7048e8', ADDRESS: '#e8890c', IP: '#0d9488', URL: '#0d9488',
  APIKEY: '#e03131', PROJECT: '#7048e8', ORG: '#4361ee', PHI: '#e03131', PII: '#e03131',
}

const SENS = {
  high: { zh: '高敏', color: 'bad' },
  medium: { zh: '中敏', color: 'warn' },
  low: { zh: '低敏', color: 'gray' },
}

export default function Detect() {
  const { scenario, policy } = useStore()
  const [text, setText] = useState(SCENARIOS[scenario].sample)
  const [result, setResult] = useState(null)
  const [live, setLive] = useState(null)

  // 实时检测（防抖）
  useEffect(() => {
    const t = setTimeout(() => {
      if (text.trim()) api.detect(text, scenario).then(setLive).catch(() => {})
      else setLive(null)
    }, 350)
    return () => clearTimeout(t)
  }, [text, scenario])

  async function runDetect() {
    setResult(await api.detect(text, scenario))
  }

  function highlight(txt, entities, plain) {
    if (!entities?.length) return txt
    const parts = []
    let last = 0
    for (const e of [...entities].sort((a, b) => a.start - b.start)) {
      if (e.start > last) parts.push(txt.slice(last, e.start))
      const color = ENTITY_COLORS[e.type] || '#4361ee'
      parts.push(
        <mark
          key={`${e.start}-${e.type}`}
          className="rounded px-0.5 font-medium"
          style={{ color, background: color + (plain ? '12' : '20'), boxShadow: `inset 0 -2px 0 ${color}55` }}
          title={`${e.zh || e.type} · 置信度 ${(e.confidence * 100).toFixed(0)}% · ${e.method}`}
        >
          {e.value}
        </mark>,
      )
      last = e.end
    }
    if (last < txt.length) parts.push(txt.slice(last))
    return parts
  }

  return (
    <div>
      <PageHeader
        icon="✂️"
        title="输入脱敏"
        subtitle="NLP + 正则 + 词典识别敏感实体，按策略脱敏；映射表 AES-256-GCM 加密，主密钥不出本地"
        badge={<Badge color="vault">当前策略：{policy.mode === 'placeholder' ? '占位符' : policy.mode === 'mask' ? '掩码' : '哈希'}</Badge>}
      />
      <div className="px-8 py-6 max-w-6xl space-y-4">
        <Card title="明文输入（实时检测）" icon="⌨️" accent="vault">
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={4}
            className="w-full rounded-lg bg-paper border border-line focus:border-vault-400 focus:ring-2 focus:ring-vault-100 outline-none p-3 text-[13px] text-ink resize-y transition-all"
          />
          {/* 实时高亮 */}
          {live && live.entities.length > 0 && (
            <div className="mt-2.5 p-3 rounded-lg border border-vault-200 bg-vault-50/50">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[10px] font-semibold text-vault-700 uppercase tracking-wider">🛡 实时检测</span>
                <span className="text-[10px] text-ink-faint">{live.entities.length} 个敏感实体</span>
              </div>
              <div className="text-[13px] leading-relaxed">{highlight(live.original, live.entities, true)}</div>
            </div>
          )}
          <div className="mt-3">
            <PrimaryButton onClick={runDetect} icon="✂️">识别敏感实体</PrimaryButton>
          </div>
        </Card>

        {result && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card title="实体高亮" icon="🎨" accent="warn">
                <div className="text-[13px] leading-relaxed">{highlight(result.original, result.entities)}</div>
              </Card>
              <Card title={`脱敏结果（${result.entities.length} 个实体已保护）`} icon="🔒" accent="vault">
                <div className="text-[13px] leading-relaxed mono text-vault-800 bg-vault-50/60 rounded-lg p-3 border border-vault-100">{result.redacted}</div>
              </Card>
            </div>

            <Card title="识别实体明细" icon="🏷️" accent="violet">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {result.entities.map((e, i) => {
                  const c = ENTITY_COLORS[e.type] || '#4361ee'
                  const s = SENS[e.sensitivity] || SENS.medium
                  return (
                    <div key={i} className="p-2.5 rounded-xl border border-line bg-surface">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full" style={{ background: c }} />
                        <span className="text-[12px] font-semibold text-ink">{e.zh}</span>
                        <span className="mono text-[10px] text-ink-faint">{e.placeholder}</span>
                        <Badge color={s.color}>{s.zh}</Badge>
                      </div>
                      <div className="text-[11px] text-ink-soft mt-1.5">{e.value}</div>
                      <div className="flex items-center gap-2 mt-1.5">
                        <div className="flex-1 h-1 rounded-full bg-paper overflow-hidden">
                          <div className="h-full rounded-full bg-vault-500" style={{ width: `${e.confidence * 100}%` }} />
                        </div>
                        <span className="text-[9px] mono text-ink-faint">{(e.confidence * 100).toFixed(0)}%</span>
                        <span className="text-[9px] text-ink-faint">{e.method}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </Card>

            <Card title="脱敏映射表（出站前将 AES-256-GCM 加密）" icon="🗂️" accent="ok">
              <div className="receipt p-3">
                {Object.entries(result.mapping).map(([ph, val]) => (
                  <div key={ph} className="flex items-center gap-2 text-[11px] mono py-0.5">
                    <span className="text-vault-700 w-28">{ph}</span>
                    <span className="text-ink-faint">→</span>
                    <span className="text-ink">{val}</span>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-ink-faint mt-2">⚠️ 主密钥不出本地，映射表密文仅用于回程还原，服务商全程不可见</p>
            </Card>
          </motion.div>
        )}
      </div>
    </div>
  )
}
