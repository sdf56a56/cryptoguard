// 发送进度状态机(Task 14,SSE 单流驱动)—— 纯函数,便于 vitest
// 八阶段与后端 chat_service.STAGES 同序;节点仅在 stage.status=="done" 时点亮

export const STAGES = [
  { key: 'detect', label: '检测' },
  { key: 'tokenize', label: '切分' },
  { key: 'package', label: '打包' },
  { key: 'hash', label: '哈希' },
  { key: 'dispatch', label: '派发' },
  { key: 'verify', label: '验证' },
  { key: 'restore', label: '还原' },
  { key: 'persist', label: '落盘' },
]

export function initProgress() {
  return {
    nodes: Object.fromEntries(STAGES.map((s) => [s.key, 'pending'])),
    timing: {},      // stage → t_ms(done 帧带)
    content: '',     // content 轨(token.reasoning=false)
    reasoning: '',   // reasoning 轨(token.reasoning=true,仅本地)
    status: 'streaming', // streaming | done | error
    done: null,      // done 终帧载荷
    error: null,     // {class, message}
  }
}

/**
 * 帧 → 新状态(不可变)。frame = {kind: 'stage'|'token'|'done'|'error', data}。
 * 终帧(done/error)后忽略一切后续帧(幂等收尾)。
 */
export function reduceProgress(state, frame) {
  const { kind, data } = frame || {}
  if (state.status !== 'streaming') return state

  switch (kind) {
    case 'stage': {
      const key = data?.stage
      if (!(key in state.nodes)) return state
      const nodes = {
        ...state.nodes,
        [key]: data.status === 'done' ? 'done' : data.status === 'start' ? 'running' : state.nodes[key],
      }
      const timing = data.status === 'done' ? { ...state.timing, [key]: data.t_ms } : state.timing
      return { ...state, nodes, timing }
    }
    case 'token':
      return data?.reasoning
        ? { ...state, reasoning: state.reasoning + (data.delta ?? '') }
        : { ...state, content: state.content + (data.delta ?? '') }
    case 'done':
      return { ...state, status: 'done', done: data }
    case 'error':
      return { ...state, status: 'error', error: data }
    default:
      return state
  }
}
