import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { Badge, EmptyState, KeyValue, StatusDot } from '../ui.jsx'

describe('基础 UI', () => {
  it('空态使用真实文案而不是占位数据', () => {
    const html = renderToStaticMarkup(
      <EmptyState title="还没有请求" description="通过网关发起请求后出现" />,
    )
    expect(html).toContain('还没有请求')
    expect(html).toContain('通过网关发起请求后出现')
  })

  it('状态只用有限语义色', () => {
    const html = renderToStaticMarkup(<Badge tone="bad" dot>已失败</Badge>)
    expect(html).toContain('已失败')
    expect(html).toContain('bg-bad')
    expect(renderToStaticMarkup(<StatusDot tone="ok">已配置</StatusDot>)).toContain('已配置')
  })

  it('键值行支持复制值', () => {
    const html = renderToStaticMarkup(
      <KeyValue label="请求 ID" mono copy="cg-123">cg-123</KeyValue>,
    )
    expect(html).toContain('请求 ID')
    expect(html).toContain('cg-123')
    expect(html).toContain('复制')
  })
})
