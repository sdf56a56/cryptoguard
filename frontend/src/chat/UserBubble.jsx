import { Link } from 'react-router-dom'
import { Badge } from '../components/ui.jsx'
import { splitSegments } from './highlight.js'
import useDebouncedDetect from './useDebouncedDetect.js'

// user 气泡:user_view 明文 + 敏感片段下划线(300ms debounce 检测)+ 文件卡片 + 复制/查看过程
// entities 由外部注入(历史消息用 artifacts.entities)时跳过 debounce 检测
export default function UserBubble({ text = '', entities, files = [], messageId }) {
  const detected = useDebouncedDetect(entities ? null : text)
  const ents = entities ?? detected.entities
  const segs = splitSegments(text, ents)

  return (
    <div className="flex justify-end">
      <div className="max-w-[560px] rounded-2xl rounded-tr-md border border-vault-200 bg-vault-50 px-4 py-3 shadow-card">
        <div className="text-[10px] text-ink-faint mono mb-1 text-right">用户 · 本地明文</div>
        <div className="text-[14px] text-ink whitespace-pre-wrap break-words leading-relaxed">
          {segs.map((s, i) =>
            s.entity ? (
              <span
                key={i}
                data-entity={s.entity.type}
                title={(s.entity.zh || s.entity.type) + ' · 敏感片段'}
                className="underline decoration-warn decoration-2 underline-offset-2 bg-warn-soft/60 rounded-sm px-0.5"
              >
                {s.text}
              </span>
            ) : (
              <span key={i}>{s.text}</span>
            ),
          )}
          {detected.pending && <span className="text-ink-faint text-xs ml-1">(检测中…)</span>}
        </div>

        {files.length > 0 && (
          <div className="mt-2 space-y-1.5">
            {files.map((f, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg border border-vault-200 bg-surface px-2.5 py-1.5">
                <span className="text-xs">📎</span>
                <span className="text-xs text-ink font-medium truncate max-w-[160px]">{f.name}</span>
                {f.file_hash && (
                  <span className="mono text-[10px] text-ink-faint">{f.file_hash.slice(0, 12)}…</span>
                )}
                <Badge color={f.channel === 'readable' ? 'vault' : 'gray'}>
                  {f.channel === 'readable' ? '可读通道' : '证据通道'}
                </Badge>
              </div>
            ))}
          </div>
        )}

        <div className="mt-2 flex items-center gap-3 text-[11px] text-ink-soft">
          <button
            type="button"
            className="hover:text-vault-700 transition-colors"
            onClick={() => navigator.clipboard?.writeText(text)}
          >
            复制
          </button>
          {messageId && (
            <Link to={'/inspect/' + messageId} className="hover:text-vault-700 transition-colors underline decoration-vault-300 underline-offset-2">
              查看过程
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}
