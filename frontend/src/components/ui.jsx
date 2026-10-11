import { motion } from 'framer-motion'

// 浅色「加密账本」基础组件

export function Card({ title, icon, children, className = '', accent = 'vault', right = null }) {
  const borders = {
    vault: 'border-l-vault-500',
    ok: 'border-l-ok',
    bad: 'border-l-bad',
    warn: 'border-l-warn',
    violet: 'border-l-crypto-violet',
    plain: 'border-l-line-strong',
  }
  return (
    <div className={`rounded-xl border border-line bg-surface shadow-card ${borders[accent] || borders.vault} ${className}`}>
      {title && (
        <div className="flex items-center gap-2 px-4 pt-3.5 pb-2.5 border-b border-line/70">
          {icon && <span className="text-base">{icon}</span>}
          <h3 className="text-[13px] font-semibold text-ink tracking-wide">{title}</h3>
          <div className="ml-auto">{right}</div>
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}

export function Badge({ children, color = 'vault', pulse = false, icon }) {
  const colors = {
    vault: 'bg-vault-50 text-vault-700 border-vault-200',
    ok: 'bg-ok-soft text-ok border-ok/25',
    bad: 'bg-bad-soft text-bad border-bad/25',
    warn: 'bg-warn-soft text-warn border-warn/25',
    violet: 'bg-crypto-violetSoft text-crypto-violet border-crypto-violet/25',
    gray: 'bg-paper text-ink-soft border-line',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-medium ${colors[color] || colors.vault} ${pulse ? 'alert-pulse' : ''}`}>
      {icon && <span>{icon}</span>}
      {children}
    </span>
  )
}

export function PageHeader({ title, subtitle, icon, badge }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: 'easeOut' }}
      className="px-8 pt-8 pb-5 border-b border-line bg-gradient-to-b from-white to-paper"
    >
      <div className="flex items-center gap-3">
        {icon && (
          <span className="h-11 w-11 rounded-xl bg-vault-50 border border-vault-200 flex items-center justify-center text-xl">
            {icon}
          </span>
        )}
        <div>
          <h1 className="display text-[26px] font-bold text-ink leading-tight tracking-tight">{title}</h1>
          {subtitle && <p className="text-[13px] text-ink-soft mt-1">{subtitle}</p>}
        </div>
        {badge && <div className="ml-auto">{badge}</div>}
      </div>
    </motion.div>
  )
}

// 密码数据收据行：等宽展示哈希/签名
export function HashLine({ label, value, shorten = false }) {
  const shown = shorten && value?.length > 42 ? value.slice(0, 42) + '…' : value
  return (
    <div className="flex items-baseline gap-3 text-xs py-1.5">
      <span className="text-ink-faint mono shrink-0 w-32 text-[11px]">{label}</span>
      <span className="mono text-ink break-all bg-vault-50/60 px-2 py-1 rounded flex-1 border border-vault-100">{shown}</span>
    </div>
  )
}

// 验证印章
export function Stamp({ ok, label }) {
  return (
    <motion.div
      initial={{ scale: 1.6, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 320, damping: 18 }}
      className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg border-2 font-semibold text-sm ${
        ok
          ? 'border-ok text-ok bg-ok-soft shadow-stamp'
          : 'border-bad text-bad bg-bad-soft alert-pulse'
      }`}
    >
      <span className="text-lg">{ok ? '✓' : '✗'}</span>
      {label || (ok ? '验证通过' : '验证失败')}
    </motion.div>
  )
}

// 主按钮
export function PrimaryButton({ children, onClick, disabled, icon, className = '' }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-vault-500 text-white text-sm font-semibold shadow-[0_2px_8px_-2px_rgba(67,97,238,0.5)] hover:bg-vault-600 active:scale-[0.98] transition-all disabled:opacity-50 disabled:pointer-events-none ${className}`}
    >
      {icon && <span>{icon}</span>}
      {children}
    </button>
  )
}

export function GhostButton({ children, onClick, disabled, icon, className = '' }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-line bg-surface text-ink text-sm font-medium hover:border-vault-300 hover:text-vault-700 active:scale-[0.98] transition-all disabled:opacity-50 ${className}`}
    >
      {icon && <span>{icon}</span>}
      {children}
    </button>
  )
}
