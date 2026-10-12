import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import AuditView from '../AuditView.jsx'
import {
  userMessage,
  assistantMessage,
  chainEntries,
  proofData,
  preimageResultMatch,
  preimageResultMismatch,
  hex,
} from './fixtures.js'

const render = (el) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)

const baseProps = {
  message: userMessage,
  artifacts: userMessage.artifacts,
  verification: userMessage.verification,
  chainEntries,
}

// 验收③:审计视角 proof/preimage 数据齐全
test('审计视角:Merkle 证明面板(proof 路径 + root + verified)', () => {
  const html = render(<AuditView {...baseProps} proof={proofData} preimageResult={preimageResultMatch} />)
  expect(html).toContain('Merkle')
  expect(html).toContain(hex('7')) // root
  expect(html).toContain(hex('3')) // leaf
  expect(html).toContain(hex('9')) // sibling
  expect(html).toContain('proof')
})

test('审计视角:独立复算面板三值并列(expected_hash/recomputed_hash/match)+ 复制复算材料', () => {
  const html = render(<AuditView {...baseProps} preimageResult={preimageResultMatch} />)
  expect(html).toContain('expected_hash')
  expect(html).toContain('recomputed_hash')
  expect(html).toContain(hex('e'))
  expect(html).toContain('复制复算材料')
  expect(html).toContain('两值一致')
})

test('独立复算:match=false 显示「两值不一致」', () => {
  const html = render(<AuditView {...baseProps} preimageResult={preimageResultMismatch} />)
  expect(html).toContain('两值不一致')
  expect(html).toContain(hex('a'))
})

// 验收③(硬性):proof/preimage 面板零「验证结论」措辞 —— 只允许 一致/不一致
test('独立复算面板:无「通过/可信」结论措辞', () => {
  const html = render(<AuditView {...baseProps} preimageResult={preimageResultMatch} />)
  expect(html).not.toMatch(/通过/)
  expect(html).not.toMatch(/可信/)
})

test('审计视角:哈希链定位 — chain_refs 高亮 + 消息↔链双向跳转', () => {
  const html = render(<AuditView {...baseProps} />)
  expect(html).toContain('QUERY')
  expect(html).toContain('RESPONSE')
  expect(html).toContain('/inspect/msg_prev') // 链条目 → 消息跳转
  expect(html).toContain('msg_user1') // 本消息条目高亮标注
})

test('审计视角:流水线时间线(无分阶段耗时时不造数,展示验证层与收据字段)', () => {
  const html = render(<AuditView {...baseProps} />)
  expect(html).toContain('流水线')
  expect(html).toContain('不造数')
})

test('审计视角:assistant 收据字段 response_hash/signature 渲染', () => {
  const html = render(
    <AuditView
      message={assistantMessage}
      artifacts={assistantMessage.artifacts}
      verification={assistantMessage.verification}
      chainEntries={[]}
    />,
  )
  expect(html).toContain('response_hash')
  expect(html).toContain(hex('6'))
  expect(html).toContain('signature')
})

test('审计视角:四层验证 panel(layer/ok/detail + 归约徽章取自 detail)', () => {
  const html = render(<AuditView {...baseProps} />)
  for (const v of userMessage.verification) {
    expect(html).toContain(v.layer)
    expect(html).toContain(v.detail.slice(0, 6))
  }
})

test('审计视角:reasoning 密文 sealed 标注「仅本地展示·不参与多轮回传」', () => {
  const html = render(
    <AuditView
      message={assistantMessage}
      artifacts={assistantMessage.artifacts}
      verification={assistantMessage.verification}
      chainEntries={[]}
    />,
  )
  expect(html).toContain('仅本地展示·不参与多轮回传')
  expect(html).toContain(hex('5', 48)) // sealed blob 密文体
})

test('审计视角:校验失败时红态定位到失败层', () => {
  const failed = [
    { layer: '输入绑定/防重放', ok: true, detail: 'nonce/timestamp 与出站包一致,且落在 5 分钟时间窗内' },
    { layer: '模型身份', ok: false, detail: 'model_cert 审计签名无效' },
    { layer: '响应完整性', ok: true, detail: 'response_hash 一致且签名有效' },
    { layer: '可审计日志', ok: true, detail: '已追加哈希链条目(entry_type=QUERY)并更新 Merkle 根' },
  ]
  const html = render(<AuditView {...baseProps} verification={failed} />)
  expect(html).toContain('校验失败')
  expect(html).toContain('模型身份')
})

test('审计视角:链条目缺失红框(缺失 index)', () => {
  const html = render(<AuditView {...baseProps} chainEntries={chainEntries.slice(0, 1)} />)
  expect(html).toContain('链条目缺失')
  expect(html).toContain('#4')
})
