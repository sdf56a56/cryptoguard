import { test, expect } from 'vitest'
import { ACCEPTANCE_ROWS } from '../acceptanceRows.js'

// spec §6.3 映射表:11 行 × 行动映射(验收① 11 行全部有可点击入口)
test('验收清单:恰 11 行,每行都有可点击按钮入口', () => {
  expect(ACCEPTANCE_ROWS).toHaveLength(11)
  for (const row of ACCEPTANCE_ROWS) {
    expect(row.id, row.id).toBeTruthy()
    expect(row.item, row.id).toBeTruthy()
    expect(row.target, row.id).toBeTruthy()
    expect(row.buttons.length, row.id).toBeGreaterThan(0)
    for (const b of row.buttons) expect(b.label, row.id).toMatch(/▶/)
  }
})

test('验收清单:三条新用例 → 运行 API 映射(golden/store-scan/replay/degrade)', () => {
  const byId = Object.fromEntries(ACCEPTANCE_ROWS.map((r) => [r.id, r]))
  expect(byId['golden-set'].action).toEqual({ type: 'run', apiKind: 'golden' })
  expect(byId['sec-store'].action).toEqual({ type: 'run', apiKind: 'store-scan' })
  expect(byId['sec-replay'].action).toEqual({ type: 'run', apiKind: 'replay' })
  expect(byId['sec-degrade'].action).toEqual({ type: 'run', apiKind: 'degrade' })
  // SEC-DEGRADE-1:三选一注入(network/protocol/stream)
  expect(byId['sec-degrade'].buttons.map((b) => b.degradeKind)).toEqual([
    'network',
    'protocol',
    'stream',
  ])
})

test('验收清单:跳转族映射(PERF/BIND/SEC-ATK/ISO/PACK → 现有 Console 入口)', () => {
  const byId = Object.fromEntries(ACCEPTANCE_ROWS.map((r) => [r.id, r]))
  expect(byId['perf-budget'].action).toEqual({ type: 'jump', jumpTo: 'timing' })
  expect(byId['perf-ff1'].action).toEqual({ type: 'jump', jumpTo: 'step2-ff1' })
  expect(byId['perf-leak'].action).toEqual({ type: 'jump', jumpTo: 'step2-leak' })
  expect(byId['bind-suite'].action).toEqual({ type: 'jump', jumpTo: 'step3-tamper' })
  expect(byId['sec-atk'].action).toEqual({ type: 'jump', jumpTo: 'step5-attack' })
  expect(byId['sec-iso'].action).toEqual({ type: 'jump', jumpTo: 'step5-reset' })
  expect(byId['sec-pack'].action).toEqual({ type: 'jump', jumpTo: 'step6-pack' })
})

test('验收清单:行结构 = 验收项 | 达标线 | 实测值 | 运行按钮', () => {
  for (const row of ACCEPTANCE_ROWS) {
    expect(Object.keys(row), row.id).toEqual(expect.arrayContaining(['id', 'item', 'target', 'buttons']))
  }
})
