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
  // 会话 / 查看器 / 验收(Task 13/15/16 契约)
  createSession: (title) => req('/api/chat/sessions', { method: 'POST', body: JSON.stringify(title ? { title } : {}) }),
  listSessions: () => req('/api/chat/sessions'),
  getSession: (sid) => req('/api/chat/sessions/' + sid),
  messagePipeline: (mid) => req('/api/messages/' + mid + '/pipeline'),
  chainStatus: () => req('/api/chain'),
  chainEntryProof: (index) => req('/api/chain/entry/' + index + '/proof'),
  verifyPreimage: (preimage, expectedHash) => req('/api/verify/preimage', { method: 'POST', body: JSON.stringify({ preimage, expected_hash: expectedHash }) }),
  // 验收:getter 三查 + degrade 三分类注入(degradeKind: network|protocol|stream)
  acceptanceRun: (kind, degradeKind) =>
    kind === 'degrade'
      ? req('/api/acceptance/degrade', { method: 'POST', body: JSON.stringify({ kind: degradeKind }) })
      : req('/api/acceptance/' + kind),
  // SSE 发消息(函数声明提升,实现见下方 sendMessageSSE)
  sendMessageSSE,
}

// ------------------------------------------------------------------ #
// SSE 单流客户端(Task 13):POST 发消息 → text/event-stream 帧解析
// 帧格式(后端 _sse_frame):`event: <kind>\ndata: <json>\n\n`
// ------------------------------------------------------------------ //

/**
 * 增量 SSE 帧解析器:feed(chunk) 收字节块,按 \n\n 切帧分发 handlers[eventName](json)。
 * - 多帧粘包:一块内多帧全部分发
 * - 跨块半帧:缓冲至整帧再分发(UTF-8 多字节序列被切断也由 TextDecoder 流式模式还原)
 * - 畸形帧(非 JSON)跳过,不打断后续帧
 */
export function createSSEParser(handlers = {}) {
  let buffer = ''
  const decoder = new TextDecoder()

  function dispatchFrame(block) {
    let event = 'message'
    const dataLines = []
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('event:')) event = line.slice(6).trim()
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''))
    }
    if (dataLines.length === 0) return
    let data
    try {
      data = JSON.parse(dataLines.join('\n'))
    } catch {
      return // 畸形帧跳过
    }
    handlers[event]?.(data)
  }

  return {
    feed(chunk) {
      buffer += decoder.decode(chunk, { stream: true })
      let m
      while ((m = /\r?\n\r?\n/.exec(buffer)) !== null) {
        const block = buffer.slice(0, m.index)
        buffer = buffer.slice(m.index + m[0].length)
        dispatchFrame(block)
      }
    },
    finish() {
      buffer += decoder.decode()
      if (buffer.trim()) dispatchFrame(buffer)
      buffer = ''
    },
  }
}

/**
 * 发消息并消费 SSE 单流。
 * - payload: {text, files?: [{filename, content_b64}]}
 * - handlers: {stage?, token?, done?, error?}(终帧 done/error 后停止读流)
 * - HTTP 4xx(400 空白输入 / 429 限流等)开流前抛错:err.status + err.sseClass='protocol'
 * - fetch/读流失败抛错:err.sseClass='network'|'stream'(中途断流保留已收 token 由调用方处理)
 */
export async function sendMessageSSE(sessionId, payload, handlers = {}) {
  let res
  try {
    res = await fetch(BASE + '/api/chat/sessions/' + sessionId + '/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
  } catch (e) {
    const err = new Error('网络连接失败: ' + (e?.message || e))
    err.sseClass = 'network'
    throw err
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    const err = new Error(text || 'HTTP ' + res.status)
    err.status = res.status
    err.sseClass = 'protocol'
    throw err
  }

  let terminal = false
  const parser = createSSEParser({
    ...handlers,
    done: (d) => {
      terminal = true
      handlers.done?.(d)
    },
    error: (d) => {
      terminal = true
      handlers.error?.(d)
    },
  })

  const reader = res.body.getReader()
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      parser.feed(value)
      if (terminal) break
    }
    parser.finish()
  } catch (e) {
    const err = new Error('流读取中断: ' + (e?.message || e))
    err.sseClass = 'stream'
    throw err
  } finally {
    reader.releaseLock?.()
  }
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
