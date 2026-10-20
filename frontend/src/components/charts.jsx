import { formatNumber } from '../utils/format.js'

export function Sparkline({ points = [], height = 56, stroke = '#2563eb', fill = 'rgba(37,99,235,0.10)' }) {
  const values = points.filter((value) => Number.isFinite(Number(value))).map(Number)
  if (values.length < 2) {
    return (
      <div className="flex h-14 items-center justify-center rounded border border-dashed border-line text-[11px] text-ink-faint">
        采样中…
      </div>
    )
  }
  const width = 320
  const min = Math.min(...values)
  const max = Math.max(...values)
  const span = max - min || 1
  const step = width / (values.length - 1)
  const coords = values.map((value, index) => {
    const x = index * step
    const y = height - 4 - ((value - min) / span) * (height - 8)
    return [x, y]
  })
  const line = coords.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  const area = `${line} L${width},${height} L0,${height} Z`
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-14 w-full" preserveAspectRatio="none" role="img">
      <path d={area} fill={fill} />
      <path d={line} fill="none" stroke={stroke} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

export function BarList({ items = [], tone = 'accent', max: maxOverride }) {
  const max = maxOverride || Math.max(1, ...items.map((item) => Number(item.value) || 0))
  const barTone = {
    accent: 'bg-accent-500',
    ok: 'bg-ok',
    warn: 'bg-warn',
    bad: 'bg-bad',
    neutral: 'bg-ink-faint',
  }[tone] || 'bg-accent-500'
  if (!items.length) {
    return <p className="py-4 text-center text-[12px] text-ink-faint">暂无数据</p>
  }
  return (
    <div className="space-y-2.5">
      {items.map((item) => {
        const value = Number(item.value) || 0
        return (
          <div key={item.label} className="grid grid-cols-[minmax(70px,150px)_1fr_auto] items-center gap-3">
            <span className="truncate text-[12px] text-ink-soft" title={item.label}>{item.label}</span>
            <span className="h-1.5 overflow-hidden rounded-full bg-canvas">
              <span
                className={`block h-full rounded-full ${barTone}`}
                style={{ width: `${Math.max(2, (value / max) * 100)}%` }}
              />
            </span>
            <span className="tabular text-right text-[11.5px] text-ink">{formatNumber(value)}</span>
          </div>
        )
      })}
    </div>
  )
}

function statusTone(code) {
  const number = Number(code)
  if (number >= 500) return 'bg-bad'
  if (number >= 400) return 'bg-warn'
  if (number >= 300) return 'bg-accent-500'
  if (number >= 200) return 'bg-ok'
  return 'bg-ink-faint'
}

export function StatusBar({ counts = {} }) {
  const entries = Object.entries(counts)
    .map(([status, value]) => [status, Number(value) || 0])
    .filter(([, value]) => value > 0)
    .sort((a, b) => a[0].localeCompare(b[0]))
  const total = entries.reduce((sum, [, value]) => sum + value, 0)
  if (!total) {
    return <p className="py-4 text-center text-[12px] text-ink-faint">暂无请求</p>
  }
  return (
    <div>
      <div className="flex h-2 overflow-hidden rounded-full bg-canvas">
        {entries.map(([status, value]) => (
          <span
            key={status}
            className={`${statusTone(status)} h-full`}
            style={{ width: `${(value / total) * 100}%` }}
            title={`${status}: ${value}`}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {entries.map(([status, value]) => (
          <span key={status} className="inline-flex items-center gap-1.5 text-[11px] text-ink-soft">
            <span className={`h-1.5 w-1.5 rounded-full ${statusTone(status)}`} />
            <span className="mono">{status || '—'}</span>
            <span className="tabular text-ink-faint">{formatNumber(value)}</span>
          </span>
        ))}
      </div>
    </div>
  )
}
