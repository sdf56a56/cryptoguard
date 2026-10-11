// 计时条真值(Review Focus #5):数值原样来自后端响应,前端不四舍五入输入、不做动画模拟
export function formatMs(v, isMock = false) {
  const s = Number(v).toFixed(2);
  return isMock ? `${s} (Mock 模拟延迟)` : s;
}

// mock 段判定:mock_sleep_ms 字段为第一信号;无字段时按步骤名兜底(Mock LLM 出站调用)
export function isMockStep(step = {}) {
  if (step.mock_sleep_ms != null) return true;
  const name = String(step.step || step.name || "");
  return /LLM|出站调用|出站请求/.test(name);
}
