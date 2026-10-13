import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import AssistantBubble from '../AssistantBubble.jsx'
import PrivacyStatusBar from '../PrivacyStatusBar.jsx'

// 第四阶段验收:降级/未配置必须对用户可见,绝不把 Mock 或错误伪装成正常模型回答
function render(el) {
  return renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)
}

// ---------- 状态栏:通道展示真实模型,而非硬编码厂商名 ----------

test('状态栏:已配置且无对话时展示配置的显示名', () => {
  const html = render(
    <PrivacyStatusBar
      llmConfig={{ configured: true, model: 'deepseek-flash', display_name: 'DeepSeek V4.1 Flash' }}
    />,
  )
  expect(html).toContain('DeepSeek V4.1 Flash')
  expect(html).not.toContain('MiMo')
})

test('状态栏:优先展示本轮实际应答模型', () => {
  const html = render(
    <PrivacyStatusBar
      llmConfig={{ configured: true, model: 'deepseek-flash', display_name: 'DeepSeek V4.1 Flash' }}
      answerModel="deepseek-v4-pro"
    />,
  )
  expect(html).toContain('deepseek-v4-pro')
})

test('状态栏:未配置时明确标黄并给设置页入口', () => {
  const html = render(<PrivacyStatusBar llmConfig={{ configured: false }} />)
  expect(html).toContain('未配置模型')
  expect(html).toContain('href="/settings"')
})

test('状态栏:降级时标明「非大模型生成」', () => {
  const html = render(
    <PrivacyStatusBar degraded="mock" llmConfig={{ configured: true, model: 'deepseek-flash' }} />,
  )
  expect(html).toContain('Mock 降级中')
  expect(html).toContain('非大模型生成')
})

test('状态栏:未知配置源时不谎称可用', () => {
  const html = render(<PrivacyStatusBar />)
  expect(html).toContain('未知')
})

// ---------- 气泡:错误分类呈现 + 可操作入口 ----------

test('未配置错误渲染为可操作提示并链接设置页', () => {
  const html = render(
    <AssistantBubble error={{ class: 'unconfigured', message: '未配置大模型 API Key' }} />,
  )
  expect(html).toContain('未配置大模型')
  expect(html).toContain('前往设置')
  expect(html).toContain('href="/settings"')
  expect(html).not.toContain('内部错误') // 不用含糊文案掩盖真实原因
})

test('protocol 错误标注「不降级」', () => {
  const html = render(
    <AssistantBubble error={{ class: 'protocol', message: 'HTTP 401 Unauthorized' }} />,
  )
  expect(html).toContain('协议层错误')
  expect(html).toContain('不降级')
  expect(html).toContain('HTTP 401')
})

test('internal 错误保留原始信息', () => {
  const html = render(<AssistantBubble error={{ class: 'internal', message: 'boom' }} />)
  expect(html).toContain('内部错误')
  expect(html).toContain('boom')
})

test('未知错误类别退化为 internal 文案而非静默吞掉', () => {
  const html = render(<AssistantBubble error={{ class: 'weird', message: 'x' }} />)
  expect(html).toContain('内部错误')
})

test('降级回复显式标注为模拟回复', () => {
  const html = render(
    <AssistantBubble content="模板文本" replyMeta={{ degraded: 'mock', incomplete: false }} />,
  )
  expect(html).toContain('已切换模拟回复')
})

test('正常回复不出现任何降级/错误横幅', () => {
  const html = render(
    <AssistantBubble content="真实模型回答" replyMeta={{ model: 'deepseek-flash', degraded: null, incomplete: false }} />,
  )
  expect(html).toContain('真实模型回答')
  expect(html).not.toContain('已切换模拟回复')
  expect(html).not.toContain('未配置大模型')
  expect(html).not.toContain('内部错误')
})
