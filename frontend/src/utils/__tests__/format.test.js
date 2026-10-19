import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  formatBytes,
  formatDateTime,
  formatDurationMs,
  formatNumber,
  formatPercent,
  formatRelativeTime,
  parseJsonInput,
  shorten,
  splitList,
  toEpochMs,
} from '../format.js'

afterEach(() => {
  vi.useRealTimers()
})

describe('format', () => {
  it('时长按 ms / s 分级', () => {
    expect(formatDurationMs(12)).toBe('12 ms')
    expect(formatDurationMs(1500)).toBe('1.50 s')
    expect(formatDurationMs(65000)).toBe('1m 5s')
    expect(formatDurationMs(-1)).toBe('—')
  })

  it('秒级 epoch 与毫秒级 epoch 都兼容', () => {
    expect(toEpochMs(1_700_000_000)).toBe(1_700_000_000_000)
    expect(toEpochMs(1_700_000_000_000)).toBe(1_700_000_000_000)
    expect(toEpochMs(0)).toBe(0)
    expect(toEpochMs('2026-01-01T00:00:00Z')).toBe(Date.parse('2026-01-01T00:00:00Z'))
    expect(toEpochMs('not-a-date')).toBe(0)
  })

  it('相对时间', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:10Z'))
    expect(formatRelativeTime(1_767_225_600)).toMatch(/秒前|分钟前|小时前|天前/)
    expect(formatRelativeTime(1_767_225_610)).toBe('刚刚')
  })

  it('数字、百分比、字节与 hash 缩短', () => {
    expect(formatNumber(12345)).toBe('12,345')
    expect(formatPercent(0.1234, 1)).toBe('12.3%')
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(shorten('abcdefghijklmnopqrstuvwxyz', 5, 3)).toBe('abcde…xyz')
  })

  it('日期时间对无效值返回 —', () => {
    expect(formatDateTime(0)).toBe('—')
    expect(formatDateTime('nope')).toBe('—')
  })
})

describe('输入解析', () => {
  it('JSON 输入', () => {
    expect(parseJsonInput('  ')).toMatchObject({ ok: true, empty: true })
    expect(parseJsonInput('{"a":1}')).toMatchObject({ ok: true, value: { a: 1 } })
    expect(parseJsonInput('{oops}').ok).toBe(false)
  })

  it('模型列表去空去重', () => {
    expect(splitList('a, b\n a，c')).toEqual(['a', 'b', 'c'])
  })
})
