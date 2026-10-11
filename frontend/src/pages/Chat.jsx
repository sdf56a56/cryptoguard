import { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../api'
import { Badge, Stamp } from '../components/ui'
import { useStore } from '../store'

const ENTITY_COLORS = {
  NAME: '#e03131', ID: '#e8890c', CARD: '#e8890c', PHONE: '#e03131',
  EMAIL: '#7048e8', ADDRESS: '#e8890c', IP: '#0d9488', URL: '#0d9488',
  APIKEY: '#e03131', PROJECT: '#7048e8', ORG: '#4361ee', PHI: '#e03131', PII: '#e03131',
}

const ENTITY_ZH = {
  NAME: '姓名', ID: '身份证', CARD: '银行卡', PHONE: '手机', EMAIL: '邮箱',
  ADDRESS: '地址', IP: 'IP', URL: 'URL', APIKEY: 'API Key', PROJECT: '项目', ORG: '组织',
  PHI: 'PHI', PII: 'PII',
}

// 输入框实时检测高亮预览
function HighlightedPreview({ text, entities }) {
  if (!entities?.length) return <span className="text-ink-faint text-xs">未检测到敏感信息</span>
  const parts = []
  let last = 0
  const sorted = [...entities].sort((a, b) => a.start - b.start)
  for (const e of sorted) {
    if (e.start > last) parts.push(text.slice(last, e.start))
    parts.push(
      <span
        key={`${e.start}-${e.type}`}
        className="rounded px-0.5 font-medium"
        style={{
          color: ENTITY_COLORS[e.type] || '#4361ee',
          background: (ENTITY_COLORS[e.type] || '#4361ee') + '18',
          boxShadow: `inset 0 -2px 0 ${(ENTITY_COLORS[e.type] || '#4361ee')}55`,
        }}
      >
        {e.value}
      </span>,
    )
    last = e.end
  }
  if (last < text.length) parts.push(text.slice(last))
  return <span className="text-sm leading-relaxed">{parts}</span>
}

export default function Chat() {
  const { policy } = useStore()
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: '你好，我是 CryptoGuard 安全对话代理。你发送的内容会先在本地自动识别敏感信息并脱敏，大模型只会看到占位符；响应回程经四层可验证机制校验后在本地还原。请放心提问。',
      verified: true,
    },
  ])
  const [input, setInput] = useState('')
  const [liveDetection, setLiveDetection] = useState(null)
  const [sending, setSending] = useState(false)
  const [stepFlash, setStepFlash] = useState(null)
  const bottomRef = useRef(null)
  const detectTimer = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // 输入防抖检测
  const onInput = useCallback((v) => {
    setInput(v)
    clearTimeout(detectTimer.current)
    if (!v.trim()) {
      setLiveDetection(null)
      return
    }
    detectTimer.current = setTimeout(async () => {
      try {
        setLiveDetection(await api.detect(v, 'medical'))
      } catch { /* 忽略 */ }
    }, 350)
  }, [])

  async function send() {
    const text = input.trim()
    if (!text || sending) return
    setSending(true)
    setInput('')

    // 1. 用户消息（标记脱敏前）
    const userMsg = { role: 'user', content: text, phase: 'detecting' }
    setMessages((m) => [...m, userMsg])

    try {
      // 2. 执行流水线
      setStepFlash('正在本地识别敏感信息…')
      const result = await api.query({ text, scenario: 'medical', attributes: null })

      // 3. 更新用户消息：展示脱敏后外发内容 + 检测结果
      setMessages((m) => m.map((msg, i) =>
        i === m.length - 1 && msg.role === 'user'
          ? {
              ...msg,
              phase: 'protected',
              redacted: result.redacted_input,
              entities: result.entities,
              crypto: {
                input_hash: result.input_hash,
                nonce: result.nonce,
                signature: result.signature,
                mode: result.mode,
              },
            }
          : msg,
      ))

      setStepFlash('已脱敏加密，请求经代理发送…')
      await new Promise((r) => setTimeout(r, 450))

      // 4. 助手回复 + 验证结果
      setMessages((m) => [...m, {
        role: 'assistant',
        content: result.model_output,
        restored: result.restored_output,
        verification: result.verification,
        verified: result.status === 'verified',
        response_hash: result.response_hash,
        latency: result.total_ms,
      }])
      setStepFlash(null)
    } catch (e) {
      setMessages((m) => [...m, {
        role: 'system',
        content: '请求失败：' + e.message,
      }])
      setStepFlash(null)
    } finally {
      setSending(false)
      setLiveDetection(null)
    }
  }

  const entityCount = liveDetection?.entities?.length || 0

  return (
    <div className="flex h-screen">
      {/* 主聊天区 */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* 顶栏 */}
        <div className="px-8 py-4 border-b border-line bg-surface flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-vault-500 flex items-center justify-center text-white text-sm font-bold">💬</div>
          <div>
            <h1 className="display text-lg font-bold text-ink leading-tight">安全对话</h1>
            <p className="text-[11px] text-ink-faint">用户 ⇄ CryptoGuard 代理 ⇄ 大模型 · 敏感信息永不以明文出站</p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge color="ok" icon="●">代理运行中</Badge>
            <Badge color="vault">{policy.mode === 'placeholder' ? '占位符脱敏' : policy.mode === 'mask' ? '掩码脱敏' : '哈希脱敏'}</Badge>
          </div>
        </div>

        {/* 消息列表 */}
        <div className="flex-1 overflow-y-auto px-8 py-6 space-y-5 bg-ledger">
          {messages.map((msg, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div className={`max-w-[72%] ${msg.role === 'user' ? 'items-end' : 'items-start'} flex flex-col gap-1.5`}>
                {/* 头像与名称 */}
                <div className={`flex items-center gap-2 text-[11px] text-ink-faint ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                  <span className={`h-6 w-6 rounded-full flex items-center justify-center text-[11px] ${
                    msg.role === 'user' ? 'bg-ink text-white' : msg.role === 'system' ? 'bg-bad text-white' : 'bg-vault-500 text-white'
                  }`}>
                    {msg.role === 'user' ? '我' : msg.role === 'system' ? '!' : 'AI'}
                  </span>
                  {msg.role === 'user' ? '用户输入（本地）' : msg.role === 'system' ? '系统' : 'CryptoGuard 回复'}
                </div>

                {/* 用户消息卡片 */}
                {msg.role === 'user' && (
                  <div className="rounded-2xl rounded-tr-md bg-white border border-line shadow-card overflow-hidden">
                    {/* 原始输入 */}
                    <div className="px-4 py-3">
                      <div className="text-[10px] text-ink-faint mono uppercase tracking-wider mb-1">raw input · 明文仅存本地</div>
                      <div className="text-[13px] text-ink leading-relaxed">{msg.content}</div>
                    </div>
                    {/* 脱敏后外发 */}
                    {msg.phase === 'protected' && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="border-t border-dashed border-vault-200 bg-vault-50/50 px-4 py-3"
                      >
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="text-[10px] text-vault-700 mono uppercase tracking-wider">outbound · 外发脱敏内容</span>
                          <Badge color="vault">{msg.entities.length} 个敏感实体已保护</Badge>
                        </div>
                        <div className="text-[13px] mono text-vault-800 leading-relaxed break-all">{msg.redacted}</div>
                        {/* 密码收据 */}
                        {msg.crypto && (
                          <div className="mt-2.5 pt-2 border-t border-vault-100 grid grid-cols-3 gap-2">
                            <div>
                              <div className="text-[9px] text-ink-faint mono uppercase">input_hash</div>
                              <div className="text-[10px] mono text-vault-700">{msg.crypto.input_hash.slice(0, 14)}…</div>
                            </div>
                            <div>
                              <div className="text-[9px] text-ink-faint mono uppercase">nonce</div>
                              <div className="text-[10px] mono text-vault-700">{msg.crypto.nonce.slice(0, 14)}…</div>
                            </div>
                            <div>
                              <div className="text-[9px] text-ink-faint mono uppercase">signature</div>
                              <div className="text-[10px] mono text-vault-700">{msg.crypto.signature.slice(0, 14)}…</div>
                            </div>
                          </div>
                        )}
                      </motion.div>
                    )}
                    {msg.phase === 'detecting' && (
                      <div className="border-t border-dashed border-line px-4 py-2 text-[11px] text-ink-faint">
                        <span className="inline-block h-3 w-3 border-2 border-vault-500 border-t-transparent rounded-full animate-spin mr-2 align-[-2px]" />
                        正在识别并保护敏感信息…
                      </div>
                    )}
                  </div>
                )}

                {/* 助手消息卡片 */}
                {msg.role === 'assistant' && (
                  <div className="rounded-2xl rounded-tl-md bg-white border border-line shadow-card px-4 py-3">
                    <div className="text-[13px] text-ink leading-relaxed">{msg.content}</div>
                    {msg.verification && (
                      <div className="mt-2.5 pt-2.5 border-t border-line space-y-1.5">
                        <div className="flex items-center gap-2">
                          <Stamp ok={msg.verified} label={msg.verified ? '四层验证通过' : '验证失败'} />
                          <span className="text-[10px] text-ink-faint mono">{msg.latency} ms</span>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                          {msg.verification.map((v) => (
                            <div key={v.layer} className="flex items-center gap-1.5 text-[10px]">
                              <span className={v.ok ? 'text-ok' : 'text-bad'}>{v.ok ? '✓' : '✗'}</span>
                              <span className="text-ink-soft">{v.layer}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 系统消息 */}
                {msg.role === 'system' && (
                  <div className="rounded-xl bg-bad-soft border border-bad/30 px-4 py-2.5 text-[12px] text-bad">{msg.content}</div>
                )}
              </div>
            </motion.div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* 输入区 */}
        <div className="border-t border-line bg-surface px-8 py-4">
          {/* 实时检测预览 */}
          <AnimatePresence>
            {liveDetection && entityCount > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 8 }}
                className="mb-2.5 rounded-xl border border-vault-200 bg-vault-50/60 px-3.5 py-2.5"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] font-semibold text-vault-700 uppercase tracking-wider">🛡 实时检测预览</span>
                  <span className="text-[10px] text-ink-faint">{entityCount} 个敏感实体将被保护</span>
                  <div className="ml-auto flex gap-1">
                    {[...new Set(liveDetection.entities.map((e) => e.type))].map((t) => (
                      <span
                        key={t}
                        className="text-[9px] px-1.5 py-0.5 rounded-full font-medium"
                        style={{ color: ENTITY_COLORS[t], background: ENTITY_COLORS[t] + '18' }}
                      >
                        {ENTITY_ZH[t] || t}
                      </span>
                    ))}
                  </div>
                </div>
                <HighlightedPreview text={liveDetection.original} entities={liveDetection.entities} />
              </motion.div>
            )}
          </AnimatePresence>

          {/* 状态行 */}
          <AnimatePresence>
            {stepFlash && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="mb-2 text-[11px] text-vault-700 flex items-center gap-2"
              >
                <span className="inline-block h-3 w-3 border-2 border-vault-500 border-t-transparent rounded-full animate-spin" />
                {stepFlash}
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex gap-2.5">
            <textarea
              value={input}
              onChange={(e) => onInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  send()
                }
              }}
              rows={2}
              placeholder="输入消息，含敏感信息将被自动识别保护…（Enter 发送）"
              className="flex-1 resize-none rounded-xl border border-line bg-paper px-4 py-3 text-[13px] text-ink placeholder:text-ink-faint focus:outline-none focus:border-vault-400 focus:ring-2 focus:ring-vault-100 transition-all"
            />
            <button
              onClick={send}
              disabled={sending || !input.trim()}
              className="self-end px-6 py-3 rounded-xl bg-vault-500 text-white text-sm font-semibold shadow-[0_2px_12px_-2px_rgba(67,97,238,0.5)] hover:bg-vault-600 active:scale-[0.97] transition-all disabled:opacity-40 disabled:pointer-events-none"
            >
              {sending ? '发送中…' : '发送'}
            </button>
          </div>
          <div className="mt-2 text-[10px] text-ink-faint">
            敏感信息在本地自动识别并脱敏，明文永不离开你的设备 · 出站仅含占位符 + 哈希 + nonce + 签名
          </div>
        </div>
      </div>

      {/* 右侧密码学面板 */}
      <aside className="w-80 border-l border-line bg-surface overflow-y-auto">
        <div className="px-5 py-4 border-b border-line">
          <h2 className="display text-sm font-bold text-ink">🛡 保护机制</h2>
          <p className="text-[11px] text-ink-faint mt-0.5">每次对话消息自动经过</p>
        </div>
        <div className="p-4 space-y-2.5">
          {[
            { n: 1, title: '敏感实体识别', desc: '13 类实体 · 正则+词典+规则', detail: '姓名/身份证/银行卡/手机/邮箱/API Key/PHI/PII…' },
            { n: 2, title: '本地脱敏', desc: '占位符 / 掩码 / 哈希 三模式', detail: '映射表 AES-256-GCM 加密，主密钥不出本地' },
            { n: 3, title: '出站加密', desc: '脱敏内容 + input_hash + nonce', detail: '大模型只看到 [NAME_1] 这类占位符' },
            { n: 4, title: '回程四层验证', desc: '输入绑定 → 模型身份 → 响应完整 → 审计', detail: 'Ed25519 签名 · response_hash · Merkle 日志链' },
            { n: 5, title: '本地还原', desc: '验证通过后解密映射表', detail: 'AI 回复中的占位符替换回明文' },
          ].map((s) => (
            <motion.div
              key={s.n}
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: s.n * 0.07 }}
              className="flex gap-3 p-2.5 rounded-lg border border-line hover:border-vault-200 hover:bg-vault-50/40 transition-colors"
            >
              <span className="h-6 w-6 rounded-full bg-vault-100 text-vault-700 text-[11px] font-bold flex items-center justify-center shrink-0">{s.n}</span>
              <div className="min-w-0">
                <div className="text-[12px] font-semibold text-ink">{s.title}</div>
                <div className="text-[10px] text-vault-700">{s.desc}</div>
                <div className="text-[10px] text-ink-faint mt-0.5 leading-snug">{s.detail}</div>
              </div>
            </motion.div>
          ))}
        </div>

        <div className="px-5 py-4 border-t border-line">
          <h2 className="display text-sm font-bold text-ink mb-2.5">📐 密码学性质</h2>
          <div className="receipt p-3 space-y-1">
            {[
              ['AES-256-GCM', 'IND-CPA + INT-CTXT'],
              ['Ed25519', 'EUF-CMA → ECDLP'],
              ['SHA-256 链', '抗第二原像'],
              ['Merkle 树', 'O(log n) 完整性证明'],
              ['Schnorr ZKP', '零知识 → DLOG'],
              ['Paillier', '加法同态 → DCR'],
            ].map(([algo, prop]) => (
              <div key={algo} className="flex items-baseline justify-between gap-2">
                <span className="mono text-[10px] text-ink font-medium">{algo}</span>
                <span className="mono text-[9px] text-ink-faint">{prop}</span>
              </div>
            ))}
          </div>
        </div>
      </aside>
    </div>
  )
}
