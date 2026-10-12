import { test, expect, vi, afterEach } from 'vitest'
import { api, sendMessageSSE, createSSEParser } from '../api.js'

// SSE 帧:`event: <kind>\ndata: <json>\n\n`(后端 _sse_frame 同形)
function frame(kind, data) {
  return `event: ${kind}\ndata: ${JSON.stringify(data)}\n\n`
}

const enc = new TextEncoder()

// 模拟 res.body.getReader():按序吐出字节块(支持把字符串编码或原始 Uint8Array 切块)
function mockSSE(chunks) {
  const bytes = chunks.map((c) => (c instanceof Uint8Array ? c : enc.encode(c)))
  const fetchMock = vi.fn(async () => {
    let i = 0
    return {
      ok: true,
      status: 200,
      body: {
        getReader() {
          return {
            async read() {
              if (i >= bytes.length) return { done: true, value: undefined }
              return { done: false, value: bytes[i++] }
            },
            releaseLock() {},
          }
        },
      },
    }
  })
  globalThis.fetch = fetchMock
  return fetchMock
}

afterEach(() => {
  delete globalThis.fetch
})

// 用例 1:粘包(多帧同块)+ 帧被切开(含多字节 UTF-8 字符被切断)
test('SSE parser: 多帧粘包与跨块半帧正确还原', async () => {
  const events = []
  const handlers = {
    stage: (d) => events.push(['stage', d]),
    done: (d) => events.push(['done', d]),
    error: (d) => events.push(['error', d]),
  }
  const f1 = frame('stage', { stage: 'detect', status: 'start', t_ms: 0 })
  const f2 = frame('stage', { stage: 'detect', status: 'done', t_ms: 12 })
  const f3 = frame('done', { message_id: 'msg_a', status: 'verified', note: '验证通过' })

  // 粘包:f1+f2 同一块到达;f3 被切开,且切点落在「验」字的 UTF-8 多字节序列中间
  const f3b = enc.encode(f3)
  const cut = f3b.indexOf(0xe9) // 「验」首字节 0xe9(3 字节序列)
  expect(cut).toBeGreaterThan(-1)
  mockSSE([f1 + f2, f3b.slice(0, cut + 1), f3b.slice(cut + 1)])

  const fetchMock = globalThis.fetch
  await sendMessageSSE('sess1', { text: '你好' }, handlers)

  expect(fetchMock).toHaveBeenCalledTimes(1)
  const [url, init] = fetchMock.mock.calls[0]
  expect(url).toContain('/api/chat/sessions/sess1/messages')
  expect(JSON.parse(init.body)).toEqual({ text: '你好' })

  expect(events).toEqual([
    ['stage', { stage: 'detect', status: 'start', t_ms: 0 }],
    ['stage', { stage: 'detect', status: 'done', t_ms: 12 }],
    ['done', { message_id: 'msg_a', status: 'verified', note: '验证通过' }],
  ])
})

// 用例 2:分轨 —— reasoning 轨与 content 轨互不混入
test('SSE parser: token 分轨(reasoning/content 两轨分离)', async () => {
  let content = ''
  let reasoning = ''
  const tokens = []
  mockSSE([
    frame('token', { delta: '你好', reasoning: false }) +
      frame('token', { delta: '思考中', reasoning: true }),
    frame('token', { delta: '，世界', reasoning: false }) +
      frame('token', { delta: '…', reasoning: true }),
    frame('done', { message_id: 'm', assistant_message_id: 'a', status: 'verified' }),
  ])

  await sendMessageSSE('sess1', { text: 'x' }, {
    token: (d) => {
      tokens.push(d)
      if (d.reasoning) reasoning += d.delta
      else content += d.delta
    },
    done: () => {},
  })

  expect(tokens.map((t) => t.reasoning)).toEqual([false, true, false, true])
  expect(content).toBe('你好，世界')
  expect(reasoning).toBe('思考中…')
})

// 用例 3:error 帧终帧分发
test('SSE parser: error 帧按 class/message 分发', async () => {
  const errors = []
  let doneCalled = false
  mockSSE([
    frame('stage', { stage: 'hash', status: 'start', t_ms: 0 }) +
      frame('error', { class: 'protocol', message: '限流:每会话每分钟最多 10 条' }),
    frame('done', { message_id: 'never' }), // 终帧后的内容不应再分发
  ])

  await sendMessageSSE('sess1', { text: 'x' }, {
    error: (d) => errors.push(d),
    done: () => { doneCalled = true },
  })

  expect(errors).toEqual([{ class: 'protocol', message: '限流:每会话每分钟最多 10 条' }])
  expect(doneCalled).toBe(false)
})

// 用例 4(附加):HTTP 4xx 在开流前拒绝 → 抛 protocol 类错误
test('sendMessageSSE: 429/400 等 HTTP 错误在开流前抛 protocol 类错误', async () => {
  globalThis.fetch = vi.fn(async () => ({
    ok: false,
    status: 429,
    text: async () => '限流:每会话每分钟最多 10 条',
  }))

  const err = await sendMessageSSE('sess1', { text: 'x' }, {}).then(
    () => null,
    (e) => e,
  )
  expect(err).toBeInstanceOf(Error)
  expect(err.status).toBe(429)
  expect(err.sseClass).toBe('protocol')
})

// 用例 5(附加):sendMessageSSE 同时挂在 api 对象上(ChatPage 经 api.* 调用)
test('api.sendMessageSSE 与命名导出同实现', async () => {
  expect(api.sendMessageSSE).toBe(sendMessageSSE)
  mockSSE([frame('done', { message_id: 'm', status: 'verified' })])
  const got = []
  await api.sendMessageSSE('sess1', { text: 'x' }, { done: (d) => got.push(d) })
  expect(got).toEqual([{ message_id: 'm', status: 'verified' }])
})

// 用例 6(附加):createSSEParser 独立可用(多帧粘包 → 一次 feed 全部分发)
test('createSSEParser: 一次 feed 多帧全部分发,默认事件名 message', () => {
  const got = []
  const parser = createSSEParser({
    token: (d) => got.push(['token', d]),
    message: (d) => got.push(['message', d]),
  })
  parser.feed(enc.encode(frame('token', { delta: 'a', reasoning: false }) + frame('token', { delta: 'b', reasoning: true })))
  parser.feed(enc.encode('\n\nevent: message\ndata: {"x":1}\n\n'))
  parser.finish()
  expect(got).toEqual([
    ['token', { delta: 'a', reasoning: false }],
    ['token', { delta: 'b', reasoning: true }],
    ['message', { x: 1 }],
  ])
})
