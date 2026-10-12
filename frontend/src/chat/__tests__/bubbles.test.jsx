import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import UserBubble from '../UserBubble.jsx'
import AssistantBubble from '../AssistantBubble.jsx'

function render(el) {
  return renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)
}

// UserBubble:敏感片段下划线高亮渲染
test('UserBubble 高亮渲染:敏感片段带下划线标记,普通文本原样', () => {
  const html = render(
    <UserBubble
      text="张伟,手机13800138000"
      entities={[{ type: 'PHONE', start: 5, end: 16 }]}
    />,
  )
  expect(html).toContain('data-entity="PHONE"')
  expect(html).toContain('13800138000')
  expect(html).toContain('underline')
  // 普通段不带实体标记
  expect(html).toContain('张伟,手机')
})

// UserBubble:文件卡片 + 操作行(复制 / 查看过程 → /inspect/:id)
test('UserBubble: 文件卡片(名+哈希短显+通道徽章)与查看过程链接', () => {
  const html = render(
    <UserBubble
      text="见附件"
      entities={[]}
      messageId="msg_abc123"
      files={[{ name: 'report.txt', file_hash: 'a'.repeat(64), channel: 'readable' }]}
    />,
  )
  expect(html).toContain('report.txt')
  expect(html).toContain('a'.repeat(12)) // 哈希短显
  expect(html).toContain('可读通道')
  expect(html).toContain('复制')
  expect(html).toContain('/inspect/msg_abc123')
})

// AssistantBubble:三失败态内联(降级黄条 / 不完整黄徽章 / protocol 红条)
test('AssistantBubble: 降级黄条「已切换模拟回复」', () => {
  const html = render(
    <AssistantBubble content="这是模拟回复" replyMeta={{ model: 'mock', incomplete: false, degraded: 'mock' }} />,
  )
  expect(html).toContain('已切换模拟回复')
  expect(html).toContain('warn')
})

test('AssistantBubble: 不完整黄徽章「回复不完整」', () => {
  const html = render(
    <AssistantBubble content="部分回复" replyMeta={{ model: 'mimo', incomplete: true, degraded: null }} />,
  )
  expect(html).toContain('回复不完整')
  expect(html).toContain('warn')
})

test('AssistantBubble: protocol 错误红条(不降级)', () => {
  const html = render(
    <AssistantBubble content="" error={{ class: 'protocol', message: '限流:请稍后再试' }} />,
  )
  expect(html).toContain('限流:请稍后再试')
  expect(html).toContain('bad')
})

// AssistantBubble:折叠 reasoning 标注「仅本地显示·不参与后续对话」
test('AssistantBubble: reasoning 折叠区标注仅本地显示', () => {
  const html = render(
    <AssistantBubble
      content="正式回复"
      reasoning="先想想…"
      replyMeta={{ model: 'mimo', incomplete: false, degraded: null }}
      messageId="msg_a1"
    />,
  )
  expect(html).toContain('仅本地显示·不参与后续对话')
  expect(html).toContain('先想想…')
  expect(html).toContain('/inspect/msg_a1')
})
