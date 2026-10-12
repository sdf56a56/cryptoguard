// 敏感片段高亮切分(UserBubble 下划线渲染用)—— 纯函数,便于 vitest
// 实体区间 [start,end) 按 (start 升序, 长度降序) 去重(与后端 detect 去重同规);
// 返回覆盖全文的非空段 [{text, entity|null}],拼接 == 原文。

export function splitSegments(text, entities) {
  if (!text) return []
  const sorted = [...(entities || [])]
    .filter((e) => Number.isInteger(e.start) && Number.isInteger(e.end) && e.end > e.start)
    .sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start))

  const kept = []
  for (const e of sorted) {
    const overlap = kept.some((s) => s.start < e.end && e.start < s.end)
    if (!overlap) kept.push(e)
  }

  const segs = []
  let pos = 0
  for (const e of kept) {
    if (e.start > pos) segs.push({ text: text.slice(pos, e.start), entity: null })
    segs.push({ text: text.slice(e.start, e.end), entity: e })
    pos = e.end
  }
  if (pos < text.length) segs.push({ text: text.slice(pos), entity: null })
  return segs
}
