import { STAGES } from './sendProgress.js'

// 八阶段节点条:stage 事件点亮(status=="done" 绿亮),token 逐字渲染在 assistant 气泡里
const NODE_CLASS = {
  pending: 'border-line-strong bg-surface text-ink-faint',
  running: 'border-vault-500 bg-vault-50 text-vault-700 alert-pulse',
  done: 'border-ok bg-ok-soft text-ok shadow-stamp',
}

export default function SendProgress({ progress }) {
  return (
    <div className="flex items-center gap-1 overflow-x-auto py-2">
      {STAGES.map((s, i) => {
        const st = progress.nodes[s.key]
        return (
          <div key={s.key} className="flex items-center gap-1">
            {i > 0 && <div className={`h-px w-5 ${progress.nodes[STAGES[i - 1].key] === 'done' ? 'bg-ok' : 'bg-line-strong'}`} />}
            <div className="flex flex-col items-center gap-1 w-12">
              <div
                data-stage={s.key}
                data-status={st}
                title={s.label + (progress.timing[s.key] != null ? ` ${progress.timing[s.key]}ms` : '')}
                className={`h-7 w-7 rounded-full border-2 flex items-center justify-center text-[11px] font-semibold transition-colors ${NODE_CLASS[st] || NODE_CLASS.pending}`}
              >
                {st === 'done' ? '✓' : st === 'running' ? '…' : i + 1}
              </div>
              <span className={`text-[10px] ${st === 'pending' ? 'text-ink-faint' : 'text-ink-soft'}`}>{s.label}</span>
              {progress.timing[s.key] != null && (
                <span className="mono text-[9px] text-ink-faint">{progress.timing[s.key]}ms</span>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
