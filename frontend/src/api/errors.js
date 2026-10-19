// 后端错误体统一为 {"error": {message, type, code, request_id}}（Anthropic 入口
// 是 {"type":"error","error":{...}}）；这里把它们收敛成一个前端可判定的错误类。

export class ApiError extends Error {
  constructor(message, { status = 0, kind = '', code = '', requestId = '', body = null } = {}) {
    super(message || '请求失败')
    this.name = 'ApiError'
    this.status = status
    this.kind = kind
    this.code = code
    this.requestId = requestId
    this.body = body
  }

  get isNetwork() {
    return this.status === 0
  }

  get isAuth() {
    return this.status === 401
  }

  get isForbidden() {
    return this.status === 403
  }

  get isNotConfigured() {
    return this.status === 503 && this.kind === 'config'
  }

  get isNotFound() {
    return this.status === 404
  }

  get isConflict() {
    return this.status === 409
  }
}

export function parseErrorPayload(data, fallback = '') {
  if (!data || typeof data !== 'object') {
    return { message: fallback || '请求失败', kind: '', code: '', requestId: '' }
  }
  const source = (data.error && typeof data.error === 'object') ? data.error : data
  return {
    message: String(source.message || source.detail || fallback || '请求失败'),
    kind: String(source.type || source.kind || ''),
    code: String(source.code || ''),
    requestId: String(source.request_id || ''),
  }
}
