import { ApiError, parseErrorPayload } from './errors.js'

let adminToken = ''

export function setAdminToken(value) {
  adminToken = (value || '').trim()
}

export function getAdminToken() {
  return adminToken
}

function authHeaders(token) {
  return token ? { 'X-Admin-Token': token } : {}
}

async function readJson(response) {
  const text = await response.text().catch(() => '')
  if (!text) return { data: null, text: '' }
  try {
    return { data: JSON.parse(text), text }
  } catch {
    return { data: null, text }
  }
}

export async function request(path, options = {}) {
  const {
    method = 'GET',
    body,
    token,
    headers = {},
    signal,
    raw = false,
  } = options
  const effectiveToken = token !== undefined ? token : adminToken
  const init = {
    method,
    signal,
    headers: { ...authHeaders(effectiveToken), ...headers },
  }
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }

  let response
  try {
    response = await fetch(path, init)
  } catch (error) {
    if (error?.name === 'AbortError') throw error
    throw new ApiError(
      '无法连接后端服务：请确认网关已在 127.0.0.1:8100 启动，且 Vite 代理目标正确',
      { status: 0, kind: 'network' },
    )
  }

  const { data, text } = await readJson(response)
  if (!response.ok) {
    const parsed = parseErrorPayload(data, text || `HTTP ${response.status}`)
    if (response.status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('cg:auth-expired'))
    }
    throw new ApiError(parsed.message, {
      status: response.status,
      kind: parsed.kind,
      code: parsed.code,
      requestId: parsed.requestId
        || response.headers.get('X-CryptoGuard-Request-ID')
        || '',
      body: data,
    })
  }
  return raw ? { data, response } : data
}

// --------------------------------------------------------------------------- //
// SSE（仅用于链路测试消费 /v1/chat/completions 的流式响应）
// --------------------------------------------------------------------------- //
export function createSSEParser(handlers = {}) {
  let buffer = ''
  const decoder = new TextDecoder()

  function dispatch(block) {
    let event = 'message'
    const dataLines = []
    for (const line of block.split(/\r?\n/)) {
      if (!line || line.startsWith(':')) continue
      if (line.startsWith('event:')) event = line.slice(6).trim()
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''))
    }
    if (!dataLines.length) return
    const text = dataLines.join('\n')
    if (text === '[DONE]') {
      handlers.done?.()
      return
    }
    let payload
    try {
      payload = JSON.parse(text)
    } catch {
      return // 畸形帧跳过，不打断后续帧
    }
    handlers[event]?.(payload)
    if (event !== 'message') handlers.message?.(payload)
  }

  return {
    feed(chunk) {
      buffer += typeof chunk === 'string'
        ? chunk
        : decoder.decode(chunk, { stream: true })
      let match
      while ((match = /\r?\n\r?\n/.exec(buffer)) !== null) {
        const block = buffer.slice(0, match.index)
        buffer = buffer.slice(match.index + match[0].length)
        dispatch(block)
      }
    },
    finish() {
      buffer += decoder.decode()
      if (buffer.trim()) dispatch(buffer)
      buffer = ''
    },
  }
}

export async function streamChatCompletion({ body, clientKey, signal, handlers = {} }) {
  let response
  try {
    response = await fetch('/v1/chat/completions', {
      method: 'POST',
      signal,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${clientKey}`,
      },
      body: JSON.stringify({ ...body, stream: true }),
    })
  } catch (error) {
    if (error?.name === 'AbortError') throw error
    throw new ApiError('无法连接网关（流式请求未发出）', { status: 0, kind: 'network' })
  }

  if (!response.ok) {
    const { data, text } = await readJson(response)
    const parsed = parseErrorPayload(data, text || `HTTP ${response.status}`)
    throw new ApiError(parsed.message, {
      status: response.status,
      kind: parsed.kind,
      code: parsed.code,
      requestId: parsed.requestId
        || response.headers.get('X-CryptoGuard-Request-ID')
        || '',
      body: data,
    })
  }
  if (!response.body) {
    throw new ApiError('网关返回了空的流式响应体', { status: 502, kind: 'stream' })
  }

  let terminal = false
  const parser = createSSEParser({
    message(frame) {
      if (frame?.error) {
        const parsed = parseErrorPayload({ error: frame.error }, '流式请求失败')
        terminal = true
        handlers.error?.(new ApiError(parsed.message, {
          status: 502,
          kind: parsed.kind || 'stream',
          requestId: parsed.requestId || frame.id || '',
          body: frame,
        }))
        return
      }
      if (frame?.usage) handlers.usage?.(frame.usage)
      if (frame?.cryptoguard) handlers.meta?.(frame.cryptoguard)
      const delta = frame?.choices?.[0]?.delta
      if (delta?.reasoning_content) handlers.reasoning?.(delta.reasoning_content)
      if (delta?.content) handlers.delta?.(delta.content)
    },
    done() {
      terminal = true
      handlers.done?.()
    },
  })

  const reader = response.body.getReader()
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      parser.feed(value)
      if (terminal) break
    }
    parser.finish()
  } catch (error) {
    if (error?.name === 'AbortError') throw error
    throw new ApiError(`流读取中断：${error?.message || error}`, {
      status: 0,
      kind: 'stream',
    })
  } finally {
    reader.releaseLock?.()
  }
}
