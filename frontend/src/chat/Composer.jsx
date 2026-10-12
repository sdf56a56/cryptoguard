import { useRef, useState } from 'react'
import { fileToBase64 } from '../api.js'
import { splitSegments } from './highlight.js'
import useDebouncedDetect from './useDebouncedDetect.js'

// 输入区:多行输入 + 附件 + 发送;发送前 300ms debounce 检测高亮预览(spec §4.1)
export default function Composer({ onSend, busy = false }) {
  const [text, setText] = useState('')
  const [files, setFiles] = useState([]) // [{filename, content_b64, size}]
  const fileRef = useRef(null)
  const { entities, pending } = useDebouncedDetect(text)
  const segs = splitSegments(text, entities)
  const canSend = !busy && (text.trim().length > 0 || files.length > 0)

  const pickFiles = async (e) => {
    const list = Array.from(e.target.files || [])
    const items = await Promise.all(
      list.map(async (f) => ({
        filename: f.name,
        content_b64: await fileToBase64(f),
        size: f.size,
      })),
    )
    setFiles((fs) => [...fs, ...items])
    if (fileRef.current) fileRef.current.value = ''
  }

  const removeFile = (idx) => setFiles((fs) => fs.filter((_, i) => i !== idx))

  const send = () => {
    if (!canSend) return
    onSend({ text, files })
    setText('')
    setFiles([])
  }

  return (
    <div className="rounded-xl border border-line bg-surface shadow-card p-3">
      {files.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-2">
          {files.map((f, i) => (
            <div key={i} className="flex items-center gap-2 rounded-lg border border-vault-200 bg-vault-50 px-2.5 py-1.5 text-xs">
              <span>📎</span>
              <span className="text-ink font-medium max-w-[180px] truncate">{f.filename}</span>
              <span className="mono text-[10px] text-ink-faint">{(f.size / 1024).toFixed(1)}KB</span>
              <button type="button" className="text-ink-faint hover:text-bad transition-colors" onClick={() => removeFile(i)}>
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            send()
          }
        }}
        rows={3}
        placeholder="输入消息,发送前自动检测敏感片段(本地先行,不出明文)…"
        className="w-full resize-y rounded-lg border border-line bg-paper/60 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:outline-none focus:border-vault-400"
      />

      {entities.length > 0 && (
        <div className="mt-1.5 rounded-lg border border-warn/25 bg-warn-soft/60 px-2.5 py-1.5">
          <div className="text-[10px] text-warn mb-1">
            检测预览 · {entities.length} 处敏感片段(发送前高亮{pending ? ' · 检测中…' : ''})
          </div>
          <div className="text-[11px] text-ink-soft whitespace-pre-wrap break-words leading-relaxed">
            {segs.map((s, i) =>
              s.entity ? (
                <span
                  key={i}
                  data-entity={s.entity.type}
                  title={s.entity.zh || s.entity.type}
                  className="underline decoration-warn decoration-2 underline-offset-2 bg-warn-soft rounded-sm px-0.5"
                >
                  {s.text}
                </span>
              ) : (
                <span key={i}>{s.text}</span>
              ),
            )}
          </div>
        </div>
      )}

      <div className="mt-2 flex items-center gap-2">
        <input ref={fileRef} type="file" multiple className="hidden" onChange={pickFiles} />
        <button
          type="button"
          onClick={() => fileRef.current?.click()}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-line bg-surface text-xs text-ink-soft hover:border-vault-300 hover:text-vault-700 transition-colors"
        >
          📎 附件
        </button>
        <span className="text-[10px] text-ink-faint">Enter 发送 · Shift+Enter 换行</span>
        <button
          type="button"
          onClick={send}
          disabled={!canSend}
          className="ml-auto inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-vault-500 text-white text-sm font-semibold shadow-[0_2px_8px_-2px_rgba(67,97,238,0.5)] hover:bg-vault-600 active:scale-[0.98] transition-all disabled:opacity-50 disabled:pointer-events-none"
        >
          {busy ? '发送中…' : '发送'}
        </button>
      </div>
    </div>
  )
}
