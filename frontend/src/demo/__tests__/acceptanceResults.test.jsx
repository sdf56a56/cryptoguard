import { test, expect } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import {
  GoldenMatrixCard,
  StoreScanResult,
  ReplayResult,
  DegradeResult,
} from '../AcceptanceResults.jsx'

const golden = {
  tp: 380,
  fp: 15,
  fn: 0,
  p: 0.962,
  r: 1.0,
  fpr: 0.04,
  p_ci: [0.9444, 0.9743],
  r_ci: [0.9944, 1.0],
  fpr_ci: [0.0254, 0.0623],
  per_type: { ID: { TP: 120, FP: 2, FN: 0 }, PHONE: { TP: 80, FP: 3, FN: 0 } },
  n_neg_units: 375,
}

test('Golden Set:混淆矩阵卡(p/r/fpr + Wilson CI + per_type)', () => {
  const html = renderToStaticMarkup(<GoldenMatrixCard result={golden} />)
  expect(html).toContain('混淆矩阵')
  expect(html).toContain('380')
  expect(html).toContain('15')
  expect(html).toContain('96.20%')
  expect(html).toContain('100.00%')
  expect(html).toContain('4.00%')
  expect(html).toContain('0.9444') // Wilson CI
  expect(html).toContain('PHONE') // per_type 表
  expect(html).toContain('120')
})

test('SEC-STORE-1:零泄漏 → 绿色「检出 0 明文」', () => {
  const html = renderToStaticMarkup(
    <StoreScanResult result={{ checked_files: 3, checked_lines: 42, leaks: [] }} />,
  )
  expect(html).toContain('检出 0 明文')
  expect(html).toContain('ok')
  expect(html).toContain('3')
  expect(html).toContain('42')
})

test('SEC-STORE-1:有泄漏 → 红色清单(file/line/path)', () => {
  const html = renderToStaticMarkup(
    <StoreScanResult
      result={{
        checked_files: 3,
        checked_lines: 42,
        leaks: [{ file: 'messages.ndjson', line: 7, path: 'user_view' }],
      }}
    />,
  )
  expect(html).toContain('bad')
  expect(html).toContain('messages.ndjson')
  expect(html).toContain('user_view')
  expect(html).toContain('7')
})

test('SEC-REPLAY-1:ok → 计数(链条目/会话/消息)', () => {
  const html = renderToStaticMarkup(
    <ReplayResult result={{ ok: true, chain_entries: 12, sessions: 2, messages: 5 }} />,
  )
  expect(html).toContain('12')
  expect(html).toContain('2')
  expect(html).toContain('5')
  expect(html).toContain('ok')
})

test('SEC-REPLAY-1:失败 → 红态 error + kind', () => {
  const html = renderToStaticMarkup(
    <ReplayResult result={{ ok: false, error: '链断:条目 3 校验和不匹配', kind: 'StoreIntegrityError' }} />,
  )
  expect(html).toContain('bad')
  expect(html).toContain('StoreIntegrityError')
  expect(html).toContain('链断')
})

test('SEC-DEGRADE-1:返回三元组逐字段渲染(kind/ui_class/degraded/incomplete)', () => {
  const html = renderToStaticMarkup(
    <DegradeResult result={{ kind: 'network', ui_class: 'yellow-degrade', degraded: 'mock', incomplete: false }} />,
  )
  expect(html).toContain('network')
  expect(html).toContain('yellow-degrade')
  expect(html).toContain('mock')
  expect(html).toContain('incomplete')
})
