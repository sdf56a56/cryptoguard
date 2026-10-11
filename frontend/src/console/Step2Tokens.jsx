import { TIER_BADGE, BADGES } from "./badges.js";

// tier → 归约 + 泄漏函数全文(芯片悬停卡)
const LEAK_DETAIL = {
  T1: { reduce: "归约:HMAC PRF 伪名不可区分", leak: "泄漏函数:等值性(同值同令牌,共指自然成立)、同值频率统计" },
  T2: { reduce: "归约:FF1 强 PRP(标准库)", leak: "泄漏函数:格式+等值性、长度/字符类/手机首段" },
  T3: { reduce: "归约:泄漏函数显式声明(保序)", leak: "泄漏函数:序关系+等值性(静态集合 ≤20,分桶降级只泄桶序)" },
  T4: { reduce: "归约:DCR(Decisional Composite Residuosity)", leak: "泄漏函数:密文形态;语义安全,计算经网关白名单" },
};

// 步骤② 令牌化:四级芯片 + 跨模态共指 + token_root 顺序链 + FF1 降级横幅
export default function Step2Tokens({ response, detect, ff1Degraded, fileItems }) {
  const tokenIndex = response?.outbound?.token_index || [];
  const tokenRoot = response?.outbound?.token_root || "";
  const entities = detect?.entities || [];

  // 跨模态共指:同值多现 → 同一令牌(T1 确定性伪名);文件名令牌与文本令牌同链
  const groups = {};
  entities.forEach((e) => {
    const k = e.value;
    (groups[k] = groups[k] || []).push(e);
  });
  const corefs = Object.entries(groups).filter(([, v]) => v.length > 1);

  if (!response) {
    return (
      <div className="rounded-xl border border-line bg-surface p-8 text-center text-ink-soft text-[13px]">
        步骤① 发送后,这里显示 CG/2.0 出站包的分级令牌索引(后端 token_index 原样渲染,前端零自算)
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* FF1 降级横幅(读 /api/perf 的 ff1_degraded;未暴露则隐藏) */}
      {ff1Degraded && (
        <div className="rounded-xl border border-warn/40 bg-warn-soft px-4 py-3 text-[13px] text-warn font-semibold">
          ⚠️ FF1 已降级为格式校验演示,演示令牌 ≤5 个(PERF-FF1-1 实测超预算,诚实降级)
        </div>
      )}

      {/* 四级令牌芯片 */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <span className="text-[13px] font-semibold text-ink">分级令牌索引 token_index</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.BIND}
          </span>
          <span className="text-[11px] text-ink-faint">悬停芯片查看泄漏函数全文 · 值全部来自后端</span>
        </div>
        <div className="p-4 flex items-start gap-2 flex-wrap">
          {tokenIndex.length === 0 && (
            <span className="text-[12px] text-ink-faint">(本次出站无令牌 —— 输入未命中敏感实体)</span>
          )}
          {tokenIndex.map((t, i) => {
            const meta = TIER_BADGE[t.tier] || TIER_BADGE.T1;
            const detail = LEAK_DETAIL[t.tier] || LEAK_DETAIL.T1;
            return (
              <div key={i} className="group relative">
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[11px] font-medium mono cursor-default ${meta.chip}`}
                >
                  {meta.badge}
                  <span className="font-semibold">{t.type}</span>
                  <span className="opacity-80 max-w-[140px] truncate">{t.token}</span>
                </span>
                {/* hover 弹卡:归约 + 泄漏函数全文 */}
                <div className="invisible opacity-0 group-hover:visible group-hover:opacity-100 transition-opacity absolute left-0 top-full mt-1 w-72 z-20 rounded-lg border border-line bg-surface shadow-lift p-3 text-[11px] text-ink-soft space-y-1">
                  <div className="font-semibold text-ink">{meta.label}</div>
                  <div className="mono break-all">token = {t.token}</div>
                  <div>显式泄漏 leak_class = {t.leak_class}</div>
                  <div>{detail.leak}</div>
                  <div className="text-vault-700">{detail.reduce}</div>
                  <div className="pt-1">
                    <span className="px-1.5 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[10px]">
                      ⚠️ 泄漏:{t.leak_class}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 跨模态共指 */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <span className="text-[13px] font-semibold text-ink">跨模态共指</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.PRF}
          </span>
          <span className="text-[11px] text-ink-faint">同值多现 → 同一令牌(T1 确定性伪名,共指碰撞 2⁻⁶⁴)</span>
        </div>
        <div className="p-4 space-y-2">
          {corefs.length === 0 && (
            <p className="text-[12px] text-ink-faint">
              暂无同值多现。文本与文件名命中同一明文时,同一会话密钥产出同一令牌(文本 ↔ 文件跨模态共指)。
            </p>
          )}
          {corefs.map(([value, list], i) => (
            <div key={i} className="flex items-center gap-2 flex-wrap rounded-lg border border-line bg-paper px-3 py-2">
              <span className="mono text-[11px] text-ink">“{value}”</span>
              <span className="text-ink-faint text-[11px]">→</span>
              <span className="text-[11px] text-ink-soft">
                {list.map((e) => `${e.zh}@${e.start}`).join(" · ")}
              </span>
              <span className="text-ink-faint text-[11px]">→</span>
              <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
                同一令牌(共指 {list.length} 处)
              </span>
            </div>
          ))}
          {fileItems?.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap rounded-lg border border-line bg-paper px-3 py-2">
              <span className="text-[11px] text-ink-soft">文件名令牌(跨模态):</span>
              {fileItems.map((f, i) => (
                <span key={i} className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] mono">
                  {f.info?.filename_token || f.file.name}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* token_root 顺序链(逐环累加,动画只滚动数字,数值取自后端) */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <span className="text-[13px] font-semibold text-ink">token_root 顺序累加链</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.BIND}
          </span>
          <span className="text-[11px] text-ink-faint">
            逐令牌顺序哈希累加,终值取自后端 outbound.token_root(前端不自算各环,动画只滚动数字)
          </span>
        </div>
        <div className="p-4 space-y-3">
          <div className="flex items-center gap-1 flex-wrap">
            <span className="px-2 py-1 rounded-full border border-line bg-paper text-[10px] mono text-ink-faint">init(sid)</span>
            <span className="text-ink-faint text-[10px]">→</span>
            {tokenIndex.map((t, i) => (
              <span key={i} className="flex items-center gap-1">
                <span className={`px-2 py-1 rounded-full border text-[10px] mono ${(TIER_BADGE[t.tier] || TIER_BADGE.T1).chip}`}>
                  {t.type}
                </span>
                {i < tokenIndex.length - 1 && <span className="text-ink-faint text-[10px]">→</span>}
              </span>
            ))}
            <span className="text-ink-faint text-[10px] ml-1">→ token_root</span>
          </div>
          {/* 链环滚动:数字来自后端 token_root,动画仅位移(动效白名单) */}
          <div className="overflow-hidden rounded-lg border border-vault-200 bg-vault-50/60 px-3 py-2">
            <div className="chain-scroll whitespace-nowrap mono text-[12px] text-vault-700">
              {`${tokenRoot}  ⟲  ${tokenRoot}`}
            </div>
          </div>
          <div className="mono text-[10px] text-ink-faint break-all">token_root = {tokenRoot}</div>
        </div>
      </div>

      {/* 映射表保险库(AES-GCM 块 + CP-ABE 策略) */}
      <div className="rounded-xl border border-line bg-surface px-4 py-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">映射表保险库</span>
          <span className="px-2 py-0.5 rounded-full border border-crypto-violet/25 bg-crypto-violetSoft text-crypto-violet text-[11px] font-medium">
            {BADGES.DCR}
          </span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.PRF}
          </span>
          <span className="text-[11px] text-ink-soft">
            明文→令牌映射经 AES-GCM 封块,授权树 CP-ABE 解封;还原仅本地(见步骤④)
          </span>
          <span className="ml-auto mono text-[11px] text-ink-faint">
            session_id = {response?.outbound?.session_id || response?.session_id || "(…)"}
          </span>
        </div>
      </div>
    </div>
  );
}
