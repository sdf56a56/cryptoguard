import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import {
  SkeletonState,
  NotFoundState,
  ChainEntryMissingState,
  VerificationFailedState,
  IncompleteBar,
  MockDegradedBadge,
} from '../states.jsx'

const render = (el) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)

// 六失败态逐态渲染(spec §4.2 线框,验收④)
test('失败态① 载入中:骨架屏', () => {
  const html = render(<SkeletonState />)
  expect(html).toContain('载入中')
  expect(html).toContain('animate-pulse')
})

test('失败态② 消息不存在:空态 + 返回入口', () => {
  const html = render(<NotFoundState messageId="msg_missing" />)
  expect(html).toContain('消息不存在')
  expect(html).toContain('msg_missing')
  expect(html).toContain('/chat')
})

test('失败态③ 链条目缺失:红框定位缺失 index', () => {
  const html = render(<ChainEntryMissingState missing={[7, 9]} />)
  expect(html).toContain('链条目缺失')
  expect(html).toContain('#7')
  expect(html).toContain('#9')
  expect(html).toContain('bad')
})

test('失败态④ 校验失败:红态定位到失败层', () => {
  const html = render(
    <VerificationFailedState layers={[{ layer: '响应完整性', detail: 'response_hash 不匹配' }]} />,
  )
  expect(html).toContain('校验失败')
  expect(html).toContain('响应完整性')
  expect(html).toContain('response_hash 不匹配')
  expect(html).toContain('bad')
})

test('失败态⑤ 不完整回复:黄条', () => {
  const html = render(<IncompleteBar />)
  expect(html).toContain('回复不完整')
  expect(html).toContain('warn')
})

test('失败态⑥ Mock 降级:黄徽章', () => {
  const html = render(<MockDegradedBadge degraded="mock" />)
  expect(html).toContain('Mock 降级')
  expect(html).toContain('warn')
})
