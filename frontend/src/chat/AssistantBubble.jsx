import { Link } from 'react-router-dom'

//: 失败类别 → 呈现风格与抬头。unconfigured 不是错误而是「待配置」,单独用黄条 + 设置入口,
//: 绝不用「内部错误」这类含糊文案掩盖真实原因(第四阶段:不允许静默降级)。
const ERROR_STYLE = {
  unconfigured: { tone: 'warn', label: '未配置大模型' },
  protocol: { tone: 'bad', label: '协议层错误（不降级）' },
  network: { tone: 'bad', label: '网络错误（不降级）' },
  stream: { tone: 'warn', label: '流中断（不降级）' },
  internal: { tone: 'bad', label: '内部错误' },
}

function ErrorNotice({ error }) {
  const style = ERROR_STYLE[error.class] || ERROR_STYLE.internal
  const tone = style.tone === 'warn'
    ? 'border-warn/25 bg-warn-soft text-warn'
    : 'border-bad/25 bg-bad-soft text-bad'
  return (
    <div className={`mb-2 rounded-lg border px-3 py-2 text-xs ${tone}`}>
      <span className="font-semibold">{style.label}：</span>
      {error.message}
      {error.class === 'unconfigured' && (
        <Link to="/settings" className="ml-2 underline decoration-current underline-offset-2 font-semibold">
          前往设置
        </Link>
      )}
    </div>
  )
}

// assistant 气泡:回复正文 + 折叠 reasoning(仅本地显示·不参与后续对话)
// 失败态内联:降级黄条「已切换模拟回复」/ 不完整黄徽章「回复不完整」/ protocol·internal 红条
export default function AssistantBubble({
  content = '',
  reasoning = '',
  replyMeta = null,
  messageId = null,
  error = null,
  streaming = false,
}) {
  const degraded = Boolean(replyMeta?.degraded)
  const incomplete = Boolean(replyMeta?.incomplete)

  return (
    <div className="flex justify-start">
      <div className="max-w-[640px] rounded-2xl rounded-tl-md border border-line bg-surface px-4 py-3 shadow-card">
        <div className="text-[10px] text-ink-faint mono mb-1">
          CryptoGuard{streaming ? ' · 生成中' : ''}
        </div>

        {error && <ErrorNotice error={error} />}

        {degraded && (
          <div className="mb-2 rounded-lg border border-warn/25 bg-warn-soft px-3 py-2 text-xs text-warn">
            已切换模拟回复(网络降级 · Mock)
          </div>
        )}

        <div className="text-[14px] text-ink whitespace-pre-wrap break-words leading-relaxed">
          {content || (streaming && !error ? <span className="text-ink-faint">…</span> : '')}
          {streaming && !error && <span className="caret text-vault-500">▍</span>}
        </div>

        {reasoning && (
          <details className="mt-2 rounded-lg border border-line bg-paper/70 px-3 py-2 group">
            <summary className="cursor-pointer text-[11px] text-ink-soft select-none list-none">
              ▸ 思考过程 · <span className="text-ink-faint">仅本地显示·不参与后续对话</span>
            </summary>
            <div className="mt-1.5 text-xs text-ink-soft whitespace-pre-wrap break-words mono">
              {reasoning}
            </div>
          </details>
        )}

        <div className="mt-2 flex items-center gap-3 text-[11px] text-ink-soft">
          {incomplete && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[11px] font-medium">
              回复不完整
            </span>
          )}
          <button
            type="button"
            className="hover:text-vault-700 transition-colors"
            onClick={() => navigator.clipboard?.writeText(content)}
          >
            复制
          </button>
          {messageId && (
            <Link
              to={'/inspect/' + messageId}
              className="hover:text-vault-700 transition-colors underline decoration-vault-300 underline-offset-2"
            >
              查看过程
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}
