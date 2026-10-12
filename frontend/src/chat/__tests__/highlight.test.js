import { test, expect } from 'vitest'
import { splitSegments } from '../highlight.js'

// 高亮切分:按实体 [start,end) 把明文切成 普通/敏感 段(UserBubble 下划线渲染用)
// 空段一律丢弃;重叠实体去重(先到者/长者优先,与后端 detect 去重同规)
test('splitSegments: 按实体区间切出敏感段', () => {
  //  0  1  2  3  4  5 ··· 15 16 17 18 19 ··· 38
  //  张 伟 , 手 机 1 ···  0 ,  邮 箱  z ···  m
  const text = '张伟,手机13800138000,邮箱zhangwei@example.com'
  const entities = [
    { type: 'PHONE', start: 5, end: 16 },
    { type: 'EMAIL', start: 19, end: 39 },
  ]
  const segs = splitSegments(text, entities)
  expect(segs.map((s) => s.text)).toEqual([
    '张伟,手机', '13800138000', ',邮箱', 'zhangwei@example.com',
  ])
  expect(segs.map((s) => (s.entity ? s.entity.type : null))).toEqual([
    null, 'PHONE', null, 'EMAIL',
  ])
  // 拼回原文无损
  expect(segs.map((s) => s.text).join('')).toBe(text)
})

test('splitSegments: 无实体 → 单段纯文本;空文本 → 空列表', () => {
  expect(splitSegments('你好,世界', [])).toEqual([{ text: '你好,世界', entity: null }])
  expect(splitSegments('', [])).toEqual([])
})

test('splitSegments: 重叠实体去重(长者优先),首尾相接不重叠', () => {
  const text = 'abc12345def'
  const segs = splitSegments(text, [
    { type: 'ID', start: 0, end: 8 },      // 长者保留
    { type: 'CARD', start: 3, end: 8 },    // 与上重叠 → 跳过
    { type: 'PHONE', start: 8, end: 11 },  // 首尾相接 → 保留
  ])
  expect(segs).toEqual([
    { text: 'abc12345', entity: { type: 'ID', start: 0, end: 8 } },
    { text: 'def', entity: { type: 'PHONE', start: 8, end: 11 } },
  ])
})

test('splitSegments: 敏感段覆盖开头/结尾不留空段', () => {
  const segs = splitSegments('13800138000 你好 13800138001', [
    { type: 'PHONE', start: 0, end: 11 },
    { type: 'PHONE', start: 15, end: 26 },
  ])
  expect(segs.map((s) => s.text)).toEqual(['13800138000', ' 你好 ', '13800138001'])
  expect(segs.every((s, i) => (i === 1 ? s.entity === null : s.entity?.type === 'PHONE'))).toBe(true)
})
