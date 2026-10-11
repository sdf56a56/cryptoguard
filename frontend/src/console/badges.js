// 十一枚安全徽章(spec §4.1):UI 铁律「无徽章不渲染」
// 六步内任何可见元素必须挂徽章说明它展示哪条安全性质,答不出就砍。
export const BADGES = {
  PRF: "🔒 PRF", PRP: "🔒 强PRP", OPE: "⚠️ 泄漏:序关系", DCR: "🔒 DCR",
  BIND: "🔗 抗第二原像", SIGN: "✍️ EUF-CMA", AUDIT: "🛡 审计签名",
  REPLAY: "⏱ 防重放", FILE: "📄 完整性存证", USER: "👤 不可抵赖",
  NLP: "⚠️ NLP·非密码学",
};

// tier → 芯片配色 + 对应徽章(Step2 令牌芯片同源口径)
export const TIER_BADGE = {
  T1: { badge: BADGES.PRF, chip: "bg-vault-50 text-vault-700 border-vault-200", label: "T1 不透明伪名" },
  T2: { badge: BADGES.PRP, chip: "bg-crypto-violetSoft text-crypto-violet border-crypto-violet/25", label: "T2 格式保留" },
  T3: { badge: BADGES.OPE, chip: "bg-warn-soft text-warn border-warn/25", label: "T3 保序" },
  T4: { badge: BADGES.DCR, chip: "bg-ok-soft text-ok border-ok/25", label: "T4 同态密文" },
};
