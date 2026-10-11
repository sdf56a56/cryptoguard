import { createContext, useContext, useState } from 'react'

// 全局共享：最近一次查询结果 + 策略状态，供各页面联动展示
const StoreContext = createContext(null)

export function StoreProvider({ children }) {
  const [lastResult, setLastResult] = useState(null)
  const [scenario, setScenario] = useState('medical')
  const [running, setRunning] = useState(false)
  const [policy, setPolicy] = useState({ mode: 'placeholder', enabled_types: [] })
  return (
    <StoreContext.Provider value={{
      lastResult, setLastResult,
      scenario, setScenario,
      running, setRunning,
      policy, setPolicy,
    }}>
      {children}
    </StoreContext.Provider>
  )
}

export function useStore() {
  return useContext(StoreContext)
}

export const SCENARIOS = {
  medical: {
    label: '医疗场景',
    sample: '患者张伟，男，45岁，身份证110101199003077777，医保卡号370000123456789，手机13800138000，邮箱zhangwei@example.com，住址北京市海淀区中关村街道1号。诊断：高血压，参与天枢计划临床试验。',
    attributes: ['role:doctor', 'dept:cardiology'],
  },
  financial: {
    label: '金融场景',
    sample: '客户王芳，银行卡6222021234567890，账户余额128000元，授信额度500000元，手机13900139000，邮箱wangfang@bank.com，工作单位北京市朝阳区建国路88号。参与玄武工程信贷项目。',
    attributes: ['role:analyst', 'level:senior'],
  },
}

// 敏感度 → 颜色映射
export const SENSITIVITY = {
  high: { label: '高敏', color: 'bad' },
  medium: { label: '中敏', color: 'warn' },
  low: { label: '低敏', color: 'gray' },
}
