import { Link } from 'react-router-dom'

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

        {error && (
          <div className="mb-2 rounded-lg border border-bad/25 bg-bad-soft px-3 py-2 text-xs text-bad">
            {error.class === 'protocol' ? '协议层错误(不降级):' : '内部错误:'} {error.message}
          </div>
        )}

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
