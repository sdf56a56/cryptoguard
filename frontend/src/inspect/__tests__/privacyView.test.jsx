import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import PrivacyView from '../PrivacyView.jsx'
import { userMessage, outboundDump, hex } from './fixtures.js'

const render = (el) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)

// 验收②:隐私视角只显加密后内容 + 本地明文对照
test('隐私视角:明文/出站并排对照 — 左本地明文,右模型实际收到', () => {
  const html = render(<PrivacyView message={userMessage} artifacts={userMessage.artifacts} />)
  // 左:本地明文(仅本机)
  expect(html).toContain('本地明文')
  expect(html).toContain('患者张伟,手机13800138000')
  // 右:模型实际收到(加密后文本)
  expect(html).toContain('模型实际收到')
  expect(html).toContain('患者[NAME#a1b2c3d4]')
})

test('隐私视角:出站包收据卡(token_root/input_hash/nonce+5分钟窗/文件双通道徽章)', () => {
  const html = render(<PrivacyView message={userMessage} artifacts={userMessage.artifacts} />)
  expect(html).toContain(hex('d')) // token_root
  expect(html).toContain(hex('e')) // input_hash
  expect(html).toContain(hex('f', 32)) // nonce
  expect(html).toContain('5 分钟')
  // 文件双通道徽章:readable→可读通道 / evidence→存证通道
  expect(html).toContain('可读通道')
  expect(html).toContain('存证通道')
})

test('隐私视角:令牌清单 T1-T4 分级芯片 + leak_class 悬停', () => {
  const html = render(<PrivacyView message={userMessage} artifacts={userMessage.artifacts} />)
  expect(html).toContain('T1')
  expect(html).toContain('T2')
  expect(html).toContain('T3')
  expect(html).toContain('T4')
  expect(html).toContain('[NAME#a1b2c3d4]')
  expect(html).toContain('equality') // leak_class 声明(hover 卡内容)
})

test('隐私视角:「这就是大模型看到的全部」折叠面板 = 出站包 JSON(mono+复制)', () => {
  const html = render(<PrivacyView message={userMessage} artifacts={userMessage.artifacts} />)
  expect(html).toContain('这就是大模型看到的全部')
  expect(html).toContain('&quot;schema_version&quot;: &quot;CG/2.0&quot;') // JSON dump(转义后)
  expect(html).toContain('复制')
})

test('隐私视角:出站侧不含本地明文(明文只出现在本地明文对照区)', () => {
  const html = render(<PrivacyView message={userMessage} artifacts={userMessage.artifacts} />)
  const jsonStart = html.indexOf('这就是大模型看到的全部')
  const jsonPanel = html.slice(jsonStart)
  expect(jsonPanel).not.toContain('张伟') // 原始 JSON 面板只有出站(脱敏)内容
  expect(jsonPanel).toContain('[NAME#a1b2c3d4]')
})
