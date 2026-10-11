// 后端 API 封装
const BASE = ''

async function req(path, options = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status}: ${text}`)
  }
  return res.json()
}

export const api = {
  health: () => req('/api/health'),
  detect: (text, scenario, mode) => req('/api/detect', { method: 'POST', body: JSON.stringify({ text, scenario, mode }) }),
  query: (payload) => req('/api/proxy/query', { method: 'POST', body: JSON.stringify(payload) }),
  logs: () => req('/api/logs'),
  tamperLog: (index) => req('/api/logs/tamper?index=' + index, { method: 'POST' }),
  sseSearch: (keyword) => req('/api/sse/search', { method: 'POST', body: JSON.stringify({ keyword }) }),
  heStats: (values) => req('/api/he/stats', { method: 'POST', body: JSON.stringify({ values }) }),
  zkpInfo: () => req('/api/zkp/info'),
  perf: () => req('/api/perf'),
  // 新增：实体目录 / 策略 / 统计
  entities: () => req('/api/entities'),
  policy: () => req('/api/policy'),
  setPolicy: (mode, enabledTypes) => req('/api/policy', { method: 'POST', body: JSON.stringify({ mode, enabled_types: enabledTypes }) }),
  stats: () => req('/api/stats'),
}
