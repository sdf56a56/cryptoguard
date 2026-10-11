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
  // CG/2.0 主入口(裁定 R7)
  query2: (payload) => req('/api/proxy/query2', { method: 'POST', body: JSON.stringify(payload) }),
  uploadFile: async (file, filenameTokenHint = '') => {
    const fd = new FormData()
    fd.append('file', file)
    if (filenameTokenHint) fd.append('filename_token_hint', filenameTokenHint)
    const res = await fetch(BASE + '/api/files/upload', { method: 'POST', body: fd })
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`)
    return res.json()
  },
  attackInject: (attack) => req('/api/attack/inject', { method: 'POST', body: JSON.stringify({ attack }) }),
  attackReset: () => req('/api/attack/reset', { method: 'POST' }),
  logsPack: () => req('/api/logs/pack', { method: 'POST' }),
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

// File → base64(query2 内联文件引用用,非密码学自算)
export function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '')
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}
