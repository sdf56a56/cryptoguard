import { test, expect } from 'vitest'
import { STAGES, initProgress, reduceProgress } from '../sendProgress.js'

// 八阶段节点顺序(detect→…→persist,与后端 chat_service.STAGES 一致)
test('SendProgress 状态机:八阶段按序点亮(仅 status=done 点亮)', () => {
  expect(STAGES.map((s) => s.key)).toEqual([
    'detect', 'tokenize', 'package', 'hash', 'dispatch', 'verify', 'restore', 'persist',
  ])

  let p = initProgress()
  expect(STAGES.every((s) => p.nodes[s.key] === 'pending')).toBe(true)

  // detect:start → running;done → 点亮。后续阶段仍 pending
  p = reduceProgress(p, { kind: 'stage', data: { stage: 'detect', status: 'start', t_ms: 0 } })
  expect(p.nodes.detect).toBe('running')
  expect(p.nodes.tokenize).toBe('pending')

  p = reduceProgress(p, { kind: 'stage', data: { stage: 'detect', status: 'done', t_ms: 12 } })
  expect(p.nodes.detect).toBe('done')
  expect(p.timing.detect).toBe(12)
  expect(p.nodes.tokenize).toBe('pending')

  // 其余七阶段逐个点亮,顺序不可乱
  for (const key of STAGES.slice(1).map((s) => s.key)) {
    p = reduceProgress(p, { kind: 'stage', data: { stage: key, status: 'start', t_ms: 0 } })
    expect(p.nodes[key]).toBe('running')
    p = reduceProgress(p, { kind: 'stage', data: { stage: key, status: 'done', t_ms: 3 } })
    expect(p.nodes[key]).toBe('done')
  }
  expect(STAGES.every((s) => p.nodes[s.key] === 'done')).toBe(true)
  expect(p.status).toBe('streaming') // 未收到 done 终帧仍算流中
})

// token 分轨:reasoning 与 content 两轨互不混入(dispatch 阶段交织到达)
test('SendProgress 状态机:token 双轨累积互不混入', () => {
  let p = initProgress()
  p = reduceProgress(p, { kind: 'stage', data: { stage: 'dispatch', status: 'start', t_ms: 0 } })
  p = reduceProgress(p, { kind: 'token', data: { delta: '你好', reasoning: false } })
  p = reduceProgress(p, { kind: 'token', data: { delta: '思考', reasoning: true } })
  p = reduceProgress(p, { kind: 'token', data: { delta: '，世界', reasoning: false } })
  p = reduceProgress(p, { kind: 'token', data: { delta: '…', reasoning: true } })

  expect(p.content).toBe('你好，世界')
  expect(p.reasoning).toBe('思考…')
  expect(p.nodes.dispatch).toBe('running')
})

// done 终帧:记录收尾载荷(降级/不完整/消息 id),状态转 done
test('SendProgress 状态机:done 终帧记录收尾载荷', () => {
  const payload = {
    message_id: 'msg_u', assistant_message_id: 'msg_a',
    verification: [{ layer: 'input_binding', ok: true, detail: '' }],
    chain_refs: [3, 4], incomplete: false, degraded: 'mock', status: 'verified',
  }
  let p = initProgress()
  p = reduceProgress(p, { kind: 'token', data: { delta: '回复', reasoning: false } })
  p = reduceProgress(p, { kind: 'done', data: payload })

  expect(p.status).toBe('done')
  expect(p.done).toEqual(payload)
  expect(p.content).toBe('回复')
})

// error 终帧:protocol/internal 分类保留,状态转 error
test('SendProgress 状态机:error 终帧保留错误分类', () => {
  let p = initProgress()
  p = reduceProgress(p, { kind: 'error', data: { class: 'protocol', message: '限流:请稍后再试' } })
  expect(p.status).toBe('error')
  expect(p.error).toEqual({ class: 'protocol', message: '限流:请稍后再试' })

  // 终帧之后仍保持终态(幂等)
  p = reduceProgress(p, { kind: 'token', data: { delta: 'x', reasoning: false } })
  expect(p.status).toBe('error')
})
