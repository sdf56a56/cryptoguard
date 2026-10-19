const numberFormatter = new Intl.NumberFormat('zh-CN')
const compactFormatter = new Intl.NumberFormat('zh-CN', {
  notation: 'compact',
  maximumFractionDigits: 1,
})

export function formatNumber(value, { compact = false } = {}) {
  const number = Number(value)
  if (!Number.isFinite(number)) return '—'
  return (compact ? compactFormatter : numberFormatter).format(number)
}

export function formatPercent(value, digits = 1) {
  const number = Number(value)
  if (!Number.isFinite(number)) return '—'
  return `${(number * 100).toFixed(digits)}%`
}

export function formatDurationMs(value) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < 0) return '—'
  if (number < 1000) return `${Math.round(number)} ms`
  if (number < 60_000) return `${(number / 1000).toFixed(number < 10_000 ? 2 : 1)} s`
  const minutes = Math.floor(number / 60_000)
  const seconds = Math.round((number % 60_000) / 1000)
  return `${minutes}m ${seconds}s`
}

export function formatBytes(value) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let size = number
  let index = 0
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024
    index += 1
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

export function toEpochMs(value) {
  if (typeof value === 'string') {
    const text = value.trim()
    if (!text) return 0
    if (!/^\d+(\.\d+)?$/.test(text)) {
      // 客户端 last_used 等字段是 ISO 8601 字符串
      const parsed = Date.parse(text)
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 0
    }
    value = Number(text)
  }
  const number = Number(value)
  if (!Number.isFinite(number) || number <= 0) return 0
  // 后端 epoch 用秒；大于 1e12 的值按毫秒处理（防御式兼容）
  return number > 1e12 ? number : number * 1000
}

export function formatDateTime(value) {
  const ms = toEpochMs(value)
  if (!ms) return '—'
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return '—'
  const pad = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export function formatTime(value) {
  const ms = toEpochMs(value)
  if (!ms) return '—'
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return '—'
  const pad = (n) => String(n).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export function formatRelativeTime(value) {
  const ms = toEpochMs(value)
  if (!ms) return '—'
  const diff = Date.now() - ms
  if (diff < 0) {
    const ahead = -diff
    if (ahead < 60_000) return '即将'
    if (ahead < 3_600_000) return `${Math.ceil(ahead / 60_000)} 分钟后`
    if (ahead < 86_400_000) return `${Math.ceil(ahead / 3_600_000)} 小时后`
    return `${Math.ceil(ahead / 86_400_000)} 天后`
  }
  if (diff < 10_000) return '刚刚'
  if (diff < 60_000) return `${Math.floor(diff / 1000)} 秒前`
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`
  if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)} 天前`
  return formatDateTime(value)
}

export function shorten(value, head = 10, tail = 6) {
  const text = String(value ?? '')
  if (text.length <= head + tail + 1) return text
  return `${text.slice(0, head)}…${text.slice(-tail)}`
}

export function sumValues(record) {
  if (!record || typeof record !== 'object') return 0
  return Object.values(record).reduce((total, value) => total + (Number(value) || 0), 0)
}

const OUTCOME_LABELS = {
  ok: '成功',
  error: '失败',
  blocked: '已阻断',
  incomplete: '不完整',
  idempotent_replay: '幂等重放',
  provider_test: '连通性测试',
  provider_config: '上游配置',
  confirmation_pending: '待确认',
  confirmation_released: '已释放',
  confirmation_approved: '已批准',
  confirmation_denied: '已拒绝',
}

const OUTCOME_TONES = {
  ok: 'ok',
  error: 'bad',
  blocked: 'bad',
  incomplete: 'warn',
  idempotent_replay: 'accent',
  provider_test: 'neutral',
  provider_config: 'accent',
  confirmation_pending: 'warn',
  confirmation_released: 'ok',
  confirmation_approved: 'ok',
  confirmation_denied: 'bad',
}

export function outcomeLabel(outcome) {
  return OUTCOME_LABELS[outcome] || outcome || '—'
}

export function outcomeTone(outcome) {
  return OUTCOME_TONES[outcome] || 'neutral'
}

export function statusCodeTone(status) {
  const code = Number(status)
  if (!Number.isFinite(code)) return 'neutral'
  if (code >= 500) return 'bad'
  if (code >= 400) return 'warn'
  if (code >= 200 && code < 300) return 'ok'
  return 'neutral'
}

export function clientExpired(client) {
  const ms = toEpochMs(client?.expires_epoch)
  return Boolean(ms) && ms <= Date.now()
}

export function clientActive(client) {
  return Boolean(client) && !client.revoked && !clientExpired(client)
}

export function parseJsonInput(text, { allowEmpty = true } = {}) {
  const raw = String(text ?? '').trim()
  if (!raw) {
    return allowEmpty
      ? { ok: true, empty: true, value: undefined }
      : { ok: false, empty: true, error: '不能为空' }
  }
  try {
    return { ok: true, empty: false, value: JSON.parse(raw) }
  } catch (error) {
    return { ok: false, empty: false, error: error.message || 'JSON 解析失败' }
  }
}

export function splitList(text) {
  return String(text ?? '')
    .split(/[\n,，]/)
    .map((item) => item.trim())
    .filter(Boolean)
    .filter((item, index, array) => array.indexOf(item) === index)
}
