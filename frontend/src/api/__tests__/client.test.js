import { afterEach, describe, expect, it, vi } from 'vitest'
import { createSSEParser, request } from '../client.js'
import { ApiError } from '../errors.js'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function mockResponse({ status = 200, body = {}, headers = {} } = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body)
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => headers[name] ?? null },
    text: async () => text,
  }
}

describe('request', () => {
  it('返回 JSON 并携带管理员令牌', async () => {
    const fetchMock = vi.fn(async () => mockResponse({ body: { ok: true } }))
    vi.stubGlobal('fetch', fetchMock)
    const data = await request('/admin/providers', {
      token: 'secret-token',
      headers: { 'X-Test': '1' },
    })
    expect(data).toEqual({ ok: true })
    const init = fetchMock.mock.calls[0][1]
    expect(init.headers['X-Admin-Token']).toBe('secret-token')
    expect(init.headers['X-Test']).toBe('1')
  })

  it('把后端错误体解析为 ApiError', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => mockResponse({
      status: 400,
      body: { error: { message: 'bad base_url', type: 'invalid_request', code: 'invalid_request', request_id: 'cg-1' } },
    })))
    await expect(request('/admin/providers', { method: 'POST', body: {} }))
      .rejects.toMatchObject({
        name: 'ApiError',
        status: 400,
        kind: 'invalid_request',
        requestId: 'cg-1',
        message: 'bad base_url',
      })
  })

  it('网络失败归类为 status=0', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('failed') }))
    const error = await request('/health').catch((err) => err)
    expect(error).toBeInstanceOf(ApiError)
    expect(error.status).toBe(0)
    expect(error.kind).toBe('network')
  })

  it('AbortError 原样抛出，不包装成网络错误', async () => {
    const abort = Object.assign(new Error('aborted'), { name: 'AbortError' })
    vi.stubGlobal('fetch', vi.fn(async () => { throw abort }))
    await expect(request('/admin/providers')).rejects.toBe(abort)
  })
})

describe('createSSEParser', () => {
  it('处理跨块、多帧、注释心跳与 [DONE]', () => {
    const deltas = []
    const done = vi.fn()
    const parser = createSSEParser({
      message: (frame) => deltas.push(frame.choices?.[0]?.delta?.content),
      done,
    })
    parser.feed(': ping\n\n')
    parser.feed('data: {"choices":[{"delta":{"content":"你"}}]}\n\ndata: {"choices":[{"delta":{"content":"好"}}]}\n')
    parser.feed('\ndata: [DONE]\n\n')
    parser.finish()
    expect(deltas).toEqual(['你', '好'])
    expect(done).toHaveBeenCalledTimes(1)
  })

  it('跨 UTF-8 字节边界也能还原', () => {
    const frames = []
    const parser = createSSEParser({ message: (frame) => frames.push(frame) })
    const bytes = new TextEncoder().encode('data: {"x":"中文"}\n\n')
    const split = 10
    parser.feed(bytes.slice(0, split))
    parser.feed(bytes.slice(split))
    parser.finish()
    expect(frames[0].x).toBe('中文')
  })

  it('畸形帧跳过，不打断后续帧', () => {
    const frames = []
    const parser = createSSEParser({ message: (frame) => frames.push(frame) })
    parser.feed('data: {not json}\n\ndata: {"ok":1}\n\n')
    parser.finish()
    expect(frames).toEqual([{ ok: 1 }])
  })
})
