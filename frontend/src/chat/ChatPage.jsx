import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api.js'
import PrivacyStatusBar from './PrivacyStatusBar.jsx'
import UserBubble from './UserBubble.jsx'
import AssistantBubble from './AssistantBubble.jsx'
import Composer from './Composer.jsx'
import SendProgress from './SendProgress.jsx'
import { initProgress, reduceProgress } from './sendProgress.js'

// /chat(spec §4.1):会话侧栏 + 消息流 + 输入区;单 SSE 驱动八阶段与逐字渲染
export default function ChatPage() {
  const [sessions, setSessions] = useState([])
  const [sid, setSid] = useState(null)
  const [messages, setMessages] = useState([])
  const [progress, setProgress] = useState(null)   // 发送中(sendProgress 状态机)
  const [error, setError] = useState(null)         // {class, message}
  const [busy, setBusy] = useState(false)
  const [chainInfo, setChainInfo] = useState(null)
  const [entityCount, setEntityCount] = useState(null)
  const [vaultOk, setVaultOk] = useState(false)
  const [llmConfig, setLlmConfig] = useState(null)   // 后端当前生效的模型配置(脱敏)
  const progressRef = useRef(null)

  const refreshChain = useCallback(() => {
    api.chainStatus().then(setChainInfo).catch(() => {})
  }, [])

  // 初始加载:会话列表(空则自动建一条)+ 隐私状态栏数据
  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        let list = await api.listSessions()
        if (!alive) return
        if (!list.length) list = [await api.createSession()]
        if (!alive) return
        setSessions(list)
        setSid((prev) => prev ?? list[0].id)
      } catch {
        /* 后端未就绪:侧栏空态 */
      }
      try {
        const [chain, ent] = await Promise.all([api.chainStatus(), api.entities()])
        if (!alive) return
        setChainInfo(chain)
        setEntityCount((ent.types || []).filter((t) => t.enabled).length)
      } catch { /* 忽略 */ }
      try {
        await api.health()
        if (alive) setVaultOk(true)
      } catch { /* 忽略 */ }
      try {
        const c = await api.llmConfig()
        if (alive) setLlmConfig(c.config || null)
      } catch { /* 忽略:状态栏退化为未知 */ }
    })()
    return () => {
      alive = false
    }
  }, [])

  // 切换/进入会话 → 拉消息(刷新后会话与消息仍在,持久化联通)
  useEffect(() => {
    if (!sid) return undefined
    let alive = true
    api
      .getSession(sid)
      .then((r) => {
        if (alive) setMessages(r.messages || [])
      })
      .catch(() => {
        if (alive) setMessages([])
      })
    return () => {
      alive = false
    }
  }, [sid])

  const handleNewSession = async () => {
    try {
      const s = await api.createSession()
      setSessions((ss) => [...ss, s])
      setSid(s.id)
      setMessages([])
      setError(null)
      setProgress(null)
    } catch { /* 忽略 */ }
  }

  const handleSend = useCallback(
    async ({ text, files }) => {
      if (!sid || busy) return
      setBusy(true)
      setError(null)
      const fresh = initProgress()
      progressRef.current = fresh
      setProgress(fresh)

      // 乐观 user 气泡(发送后回填真实 message_id)
      const localId = 'local_' + Date.now()
      setMessages((ms) => [
        ...ms,
        {
          id: localId,
          role: 'user',
          user_view: text,
          files: files.map((f) => ({ name: f.filename })),
          pending: true,
        },
      ])

      const apply = (kind, data) => {
        progressRef.current = reduceProgress(progressRef.current, { kind, data })
        setProgress(progressRef.current)
      }

      try {
        await api.sendMessageSSE(
          sid,
          { text, files: files.map((f) => ({ filename: f.filename, content_b64: f.content_b64 })) },
          {
            stage: (d) => apply('stage', d),
            token: (d) => apply('token', d),
            done: (d) => {
              apply('done', d)
              const p = progressRef.current
              setMessages((ms) => [
                ...ms.map((m) => (m.pending ? { ...m, id: d.message_id, pending: false } : m)),
                {
                  id: d.assistant_message_id,
                  role: 'assistant',
                  llm_view: p.content,
                  user_view: p.content,
                  reasoning: p.reasoning,
                  reply_meta: { model: d.model || null, incomplete: d.incomplete, degraded: d.degraded },
                  verification: d.verification,
                  chain_refs: d.chain_refs,
                  files: [],
                },
              ])
              setProgress(null)
              refreshChain()
            },
            error: (e) => {
              apply('error', e)
              setError(e)
            },
          },
        )
      } catch (err) {
        // protocol:开流前 HTTP 4xx(不降级,红条) | network:fetch 失败 | stream:读流中断(保 token,标不完整)
        const e = {
          class: err.sseClass || 'internal',
          // spec §5:429 → 「请稍后再试」文案
          message: err.status === 429 ? '请求过于频繁,请稍后再试' : err.message,
        }
        setError(e)
        if (e.class === 'stream') apply('error', e)
        else setProgress(null)
      } finally {
        setBusy(false)
      }
    },
    [sid, busy, refreshChain],
  )

  // 通道降级状态 + 实际应答模型:最近一条 assistant 的 reply_meta
  let degraded = null
  let answerModel = null
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    if (messages[i].role === 'assistant') {
      degraded = messages[i].reply_meta?.degraded || null
      answerModel = messages[i].reply_meta?.model || null
      break
    }
  }

  return (
    <div>
      <PrivacyStatusBar
        entityCount={entityCount}
        chainInfo={chainInfo}
        degraded={degraded}
        vaultOk={vaultOk}
        llmConfig={llmConfig}
        answerModel={answerModel}
      />

      <div className="mx-auto flex max-w-[1280px] gap-0 px-0">
        {/* 会话侧栏 */}
        <aside className="w-60 shrink-0 border-r border-line bg-surface/50 min-h-[calc(100vh-6.25rem)] p-3">
          <button
            type="button"
            onClick={handleNewSession}
            className="w-full mb-3 px-3 py-2 rounded-lg border border-dashed border-vault-300 text-vault-700 text-xs font-medium hover:bg-vault-50 transition-colors"
          >
            + 新会话
          </button>
          <div className="space-y-1">
            {sessions.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => setSid(s.id)}
                className={`w-full text-left px-3 py-2 rounded-lg transition-colors ${
                  s.id === sid ? 'bg-vault-50 border border-vault-200' : 'border border-transparent hover:bg-paper'
                }`}
              >
                <div className="text-xs text-ink font-medium truncate">{s.title || '新会话'}</div>
                <div className="text-[10px] text-ink-faint mono">{String(s.created || '').slice(0, 16).replace('T', ' ')}</div>
              </button>
            ))}
            {!sessions.length && <div className="text-[11px] text-ink-faint px-2 py-4 text-center">暂无会话</div>}
          </div>
        </aside>

        {/* 消息流 + 输入区 */}
        <section className="flex-1 min-w-0 flex flex-col min-h-[calc(100vh-6.25rem)]">
          <div className="flex-1 overflow-y-auto px-8 py-6 space-y-4">
            {!messages.length && !progress && (
              <div className="text-center text-ink-faint text-sm py-20">
                发送第一条消息:明文仅在本地,出站为脱敏令牌包,全程可审计。
              </div>
            )}

            {messages.map((m) =>
              m.role === 'user' ? (
                <UserBubble
                  key={m.id}
                  text={m.user_view ?? ''}
                  entities={m.artifacts?.entities}
                  files={m.files || []}
                  messageId={m.pending ? undefined : m.id}
                />
              ) : (
                <AssistantBubble
                  key={m.id}
                  content={m.user_view || m.llm_view || ''}
                  reasoning={m.reasoning || ''}
                  replyMeta={m.reply_meta}
                  messageId={m.id}
                />
              ),
            )}

            {progress && (
              <>
                <SendProgress progress={progress} />
                <AssistantBubble
                  streaming={progress.status === 'streaming'}
                  content={progress.content}
                  reasoning={progress.reasoning}
                  error={error && progress.status !== 'done' ? error : null}
                  replyMeta={
                    // 流中断保已收 token + 标不完整;protocol/internal 无回复体,不挂徽章
                    error?.class === 'stream' ? { incomplete: true } : null
                  }
                />
              </>
            )}
            {!progress && error && <AssistantBubble error={error} />}
          </div>

          <div className="px-8 pb-6">
            <Composer onSend={handleSend} busy={busy} />
          </div>
        </section>
      </div>
    </div>
  )
}
