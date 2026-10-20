import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from 'react'
import { createPortal } from 'react-dom'
import { Icon } from './Icon.jsx'
import { ApiError } from '../api/errors.js'

export function cn(...parts) {
  return parts.filter(Boolean).join(' ')
}

// --------------------------------------------------------------------------- //
// 按钮
// --------------------------------------------------------------------------- //
const BUTTON_VARIANTS = {
  primary: 'border border-accent-500 bg-accent-500 text-white hover:bg-accent-600 hover:border-accent-600',
  secondary: 'border border-line bg-surface text-ink hover:border-line-strong hover:bg-canvas',
  ghost: 'border border-transparent bg-transparent text-ink-soft hover:bg-canvas hover:text-ink',
  danger: 'border border-bad/30 bg-bad-soft text-bad hover:border-bad/60',
}

const BUTTON_SIZES = {
  sm: 'h-8 px-2.5 text-[12px] gap-1.5',
  md: 'h-9 px-3.5 text-[13px] gap-2',
}

export function Button({
  children,
  variant = 'secondary',
  size = 'md',
  busy = false,
  icon,
  className = '',
  disabled,
  type = 'button',
  ...rest
}) {
  return (
    <button
      type={type}
      disabled={disabled || busy}
      className={cn(
        'inline-flex items-center justify-center rounded-md font-medium transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-50',
        BUTTON_VARIANTS[variant] || BUTTON_VARIANTS.secondary,
        BUTTON_SIZES[size] || BUTTON_SIZES.md,
        className,
      )}
      {...rest}
    >
      {busy ? <Spinner size={14} /> : icon ? <Icon name={icon} size={15} /> : null}
      {children}
    </button>
  )
}

export function IconButton({ label, icon, className = '', ...rest }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        'inline-flex h-8 w-8 items-center justify-center rounded-md border border-transparent',
        'text-ink-faint transition-colors hover:border-line hover:bg-surface hover:text-ink',
        className,
      )}
      {...rest}
    >
      <Icon name={icon} size={16} />
    </button>
  )
}

// --------------------------------------------------------------------------- //
// 表单
// --------------------------------------------------------------------------- //
export const inputClass =
  'h-9 w-full rounded-md border border-line bg-surface px-3 text-[13px] text-ink ' +
  'placeholder:text-ink-faint focus:border-accent-500 focus:outline-none ' +
  'disabled:cursor-not-allowed disabled:bg-canvas disabled:text-ink-faint'

export function Input({ className = '', mono = false, ...rest }) {
  return <input className={cn(inputClass, mono && 'mono', className)} {...rest} />
}

export function Textarea({ className = '', mono = false, rows = 4, ...rest }) {
  return (
    <textarea
      rows={rows}
      className={cn(inputClass, 'h-auto py-2 leading-5', mono && 'mono', className)}
      {...rest}
    />
  )
}

export function Select({ className = '', children, ...rest }) {
  return (
    <select className={cn(inputClass, 'pr-8', className)} {...rest}>
      {children}
    </select>
  )
}

export function Field({ label, hint, error, required, children, className = '' }) {
  return (
    <label className={cn('block', className)}>
      {label ? (
        <span className="mb-1.5 flex items-baseline gap-1.5">
          <span className="text-[12px] font-medium text-ink">{label}</span>
          {required ? <span className="text-[11px] text-bad">*</span> : null}
          {hint ? <span className="text-[11px] text-ink-faint">{hint}</span> : null}
        </span>
      ) : null}
      {children}
      {error ? <span className="mt-1 block text-[11px] text-bad">{error}</span> : null}
    </label>
  )
}

export function Checkbox({ label, hint, className = '', ...rest }) {
  return (
    <label className={cn('flex items-start gap-2 text-[13px] text-ink', className)}>
      <input
        type="checkbox"
        className="mt-0.5 h-4 w-4 rounded border-line text-accent-500 accent-accent-500"
        {...rest}
      />
      <span>
        <span>{label}</span>
        {hint ? <span className="mt-0.5 block text-[11px] text-ink-faint">{hint}</span> : null}
      </span>
    </label>
  )
}

// --------------------------------------------------------------------------- //
// 布局与状态
// --------------------------------------------------------------------------- //
export function PageHeader({ title, description, actions }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line bg-surface px-6 py-5 lg:px-8">
      <div className="min-w-0">
        <h1 className="text-[20px] font-semibold tracking-tight text-ink">{title}</h1>
        {description ? (
          <p className="mt-1 max-w-3xl text-[12.5px] leading-5 text-ink-soft">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}

export function Card({ title, description, actions, children, className = '', bodyClass = '' }) {
  return (
    <section className={cn('rounded-lg border border-line bg-surface shadow-card', className)}>
      {title || actions ? (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3">
          <div className="min-w-0">
            {title ? <h2 className="text-[13px] font-semibold text-ink">{title}</h2> : null}
            {description ? (
              <p className="mt-0.5 text-[11.5px] leading-4 text-ink-faint">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cn('p-4', bodyClass)}>{children}</div>
    </section>
  )
}

const TONES = {
  neutral: 'border-line bg-canvas text-ink-soft',
  ok: 'border-ok/25 bg-ok-soft text-ok',
  warn: 'border-warn/25 bg-warn-soft text-warn',
  bad: 'border-bad/25 bg-bad-soft text-bad',
  accent: 'border-accent-200 bg-accent-50 text-accent-700',
}

const DOTS = {
  neutral: 'bg-ink-faint',
  ok: 'bg-ok',
  warn: 'bg-warn',
  bad: 'bg-bad',
  accent: 'bg-accent-500',
}

export function Badge({ children, tone = 'neutral', dot = false, className = '' }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium',
        TONES[tone] || TONES.neutral,
        className,
      )}
    >
      {dot ? <span className={cn('h-1.5 w-1.5 rounded-full', DOTS[tone] || DOTS.neutral)} /> : null}
      {children}
    </span>
  )
}

export function StatusDot({ tone = 'neutral', children, className = '' }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-[12px] text-ink-soft', className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', DOTS[tone] || DOTS.neutral)} />
      {children}
    </span>
  )
}

export function Kpi({ label, value, hint, tone = 'neutral', icon }) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3 shadow-card">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11.5px] font-medium text-ink-faint">{label}</span>
        {icon ? (
          <span className={cn('text-ink-faint', tone === 'bad' && 'text-bad',
            tone === 'warn' && 'text-warn', tone === 'ok' && 'text-ok')}>
            <Icon name={icon} size={15} />
          </span>
        ) : null}
      </div>
      <div className="tabular mt-1.5 text-[22px] font-semibold leading-7 text-ink">{value}</div>
      {hint ? <div className="mt-1 text-[11px] text-ink-faint">{hint}</div> : null}
    </div>
  )
}

export function Spinner({ size = 16, className = '' }) {
  return (
    <span
      className={cn('cg-spin inline-block rounded-full border-2 border-current border-r-transparent', className)}
      style={{ width: size, height: size }}
      role="status"
      aria-label="加载中"
    />
  )
}

export function Skeleton({ className = '' }) {
  return <div className={cn('animate-pulse rounded bg-canvas', className)} />
}

export function EmptyState({ icon = 'info', title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
      <span className="flex h-10 w-10 items-center justify-center rounded-full border border-line bg-canvas text-ink-faint">
        <Icon name={icon} size={18} />
      </span>
      <h3 className="mt-3 text-[14px] font-medium text-ink">{title}</h3>
      {description ? (
        <p className="mt-1 max-w-md text-[12px] leading-5 text-ink-soft">{description}</p>
      ) : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  )
}

export function ErrorState({ error, onRetry, compact = false }) {
  const message = error?.message || String(error || '未知错误')
  const isApi = error instanceof ApiError
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 text-center',
      compact ? 'py-6' : 'py-12')}>
      <span className="flex h-10 w-10 items-center justify-center rounded-full border border-bad/25 bg-bad-soft text-bad">
        <Icon name="alert" size={18} />
      </span>
      <h3 className="mt-3 text-[14px] font-medium text-ink">加载失败</h3>
      <p className="mt-1 max-w-xl text-[12px] leading-5 text-ink-soft">{message}</p>
      {isApi && (error.status || error.requestId) ? (
        <p className="mono mt-1 text-[11px] text-ink-faint">
          {error.status ? `HTTP ${error.status}` : ''}
          {error.kind ? ` · ${error.kind}` : ''}
          {error.requestId ? ` · ${error.requestId}` : ''}
        </p>
      ) : null}
      {onRetry ? (
        <Button className="mt-4" size="sm" icon="refresh" onClick={() => onRetry()}>
          重试
        </Button>
      ) : null}
    </div>
  )
}

export function CopyButton({ value, label = '复制', className = '' }) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(async () => {
    const text = String(value ?? '')
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }, [value])
  return (
    <button
      type="button"
      onClick={copy}
      className={cn(
        'inline-flex h-7 shrink-0 items-center gap-1 rounded border border-line bg-surface px-2',
        'text-[11px] text-ink-soft transition-colors hover:border-line-strong hover:text-ink',
        className,
      )}
      title={label}
    >
      <Icon name="copy" size={12} />
      {copied ? '已复制' : label}
    </button>
  )
}

export function Mono({ children, className = '' }) {
  return <span className={cn('mono text-[12px] text-ink', className)}>{children}</span>
}

export function KeyValue({ label, children, mono = false, copy, className = '' }) {
  return (
    <div className={cn('grid grid-cols-[130px_minmax(0,1fr)] items-start gap-3 py-1.5', className)}>
      <span className="text-[11.5px] leading-5 text-ink-faint">{label}</span>
      <div className={cn('flex min-w-0 items-start gap-2 text-[12.5px] leading-5 text-ink',
        mono && 'mono break-all')}>
        <div className="min-w-0 flex-1">{children ?? '—'}</div>
        {copy ? <CopyButton value={copy} label="复制" /> : null}
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------- //
// 弹窗
// --------------------------------------------------------------------------- //
export function Modal({ open, onClose, title, description, children, footer, size = 'md' }) {
  const containerRef = useRef(null)
  const titleId = useId()

  useEffect(() => {
    if (!open) return undefined
    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose?.()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const timer = setTimeout(() => {
      const focusable = containerRef.current?.querySelector(
        'input:not([disabled]), textarea:not([disabled]), select:not([disabled]), button:not([disabled])',
      )
      focusable?.focus?.()
    }, 30)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = previousOverflow
      clearTimeout(timer)
    }
  }, [open, onClose])

  if (!open) return null
  const widths = { sm: 'max-w-md', md: 'max-w-2xl', lg: 'max-w-4xl' }

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink/35 p-4 sm:p-8">
      <div className="absolute inset-0" onClick={onClose} aria-hidden="true" />
      <div
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={cn(
          'cg-fade-in relative my-4 w-full rounded-lg border border-line bg-surface shadow-pop',
          widths[size] || widths.md,
        )}
      >
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <h2 id={titleId} className="text-[15px] font-semibold text-ink">{title}</h2>
            {description ? (
              <p className="mt-1 text-[12px] leading-5 text-ink-soft">{description}</p>
            ) : null}
          </div>
          <IconButton label="关闭" icon="x" onClick={onClose} />
        </header>
        <div className="max-h-[calc(100vh-15rem)] overflow-y-auto px-5 py-4">{children}</div>
        {footer ? (
          <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-line px-5 py-3">
            {footer}
          </footer>
        ) : null}
      </div>
    </div>,
    document.body,
  )
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title = '确认操作',
  description,
  confirmLabel = '确认',
  danger = false,
  busy = false,
  children,
}) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      size="sm"
      footer={(
        <>
          <Button onClick={onClose} disabled={busy}>取消</Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            onClick={onConfirm}
            busy={busy}
          >
            {confirmLabel}
          </Button>
        </>
      )}
    >
      {children}
    </Modal>
  )
}

// --------------------------------------------------------------------------- //
// 表格
// --------------------------------------------------------------------------- //
export const tableClass = 'w-full min-w-[720px] border-collapse text-left text-[12.5px]'
export const thClass = 'whitespace-nowrap border-b border-line bg-canvas px-3 py-2 text-[11px] font-medium text-ink-faint'
export const tdClass = 'border-b border-line/70 px-3 py-2.5 align-middle text-ink'
