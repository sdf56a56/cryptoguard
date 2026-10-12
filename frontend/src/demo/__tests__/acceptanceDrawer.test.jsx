import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import AcceptanceDrawer from '../AcceptanceDrawer.jsx'
import DemoPage from '../DemoPage.jsx'
import { ACCEPTANCE_ROWS } from '../acceptanceRows.js'

const render = (el) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)

// 验收①:spec §6.3 表 11 行全部有可点击入口
test('AcceptanceDrawer:11 行全部渲染且每行有 ▶运行 按钮', () => {
  const html = render(<AcceptanceDrawer open onClose={() => {}} />)
  const rowCount = html.split('data-acceptance-row="').length - 1
  expect(rowCount).toBe(11)
  for (const row of ACCEPTANCE_ROWS) {
    expect(html, row.id).toContain(row.item)
    expect(html, row.id).toContain(`data-acceptance-btn="${row.id}"`)
    expect(html, row.id).toContain(row.buttons[0].label) // 首按钮文案可点
  }
})

test('AcceptanceDrawer:表头 = 验收项 | 达标线 | 实测值 | 运行', () => {
  const html = render(<AcceptanceDrawer open onClose={() => {}} />)
  expect(html).toContain('验收项')
  expect(html).toContain('达标线')
  expect(html).toContain('实测值')
  expect(html).toContain('运行')
})

test('AcceptanceDrawer:SEC-DEGRADE-1 三选一按钮(network/protocol/stream)', () => {
  const html = render(<AcceptanceDrawer open onClose={() => {}} />)
  expect(html).toContain('data-degrade-kind="network"')
  expect(html).toContain('data-degrade-kind="protocol"')
  expect(html).toContain('data-degrade-kind="stream"')
})

test('AcceptanceDrawer:Golden Set 运行按钮 + 三条新用例按钮文案', () => {
  const html = render(<AcceptanceDrawer open onClose={() => {}} />)
  expect(html).toContain('跑 Golden Set')
  expect(html).toContain('验落盘无明文')
  expect(html).toContain('重启回放验链')
  expect(html).toContain('跑 PERF')
})

// DemoPage 壳:演示沙箱徽章 + 顶栏提示 + 抽屉入口(验收③零回归:Console 仍在)
test('DemoPage:演示沙箱徽章 + 沙箱链提示 + 验收清单入口', () => {
  const html = render(<DemoPage />)
  expect(html).toContain('演示沙箱')
  expect(html).toContain('此模式写入沙箱链,不影响真实审计数据')
  expect(html).toContain('验收清单')
  expect(html).toContain('CryptoGuard 六步控制台') // 现有 Console 原样迁入
})
