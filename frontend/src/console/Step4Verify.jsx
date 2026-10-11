import { useEffect, useState } from "react";
import { BADGES } from "./badges.js";

// 五态状态机:正常灰 idle / 验证中蓝 checking / 通过绿 pass / 失败红 fail / 告警橙 warn
const STATE_UI = {
  idle: { label: "正常", cls: "border-line bg-paper text-ink-soft", dot: "⚪" },
  checking: { label: "验证中", cls: "border-vault-300 bg-vault-50 text-vault-700", dot: "🔵" },
  pass: { label: "通过", cls: "border-ok/30 bg-ok-soft text-ok", dot: "✅" },
  fail: { label: "失败", cls: "border-bad/30 bg-bad-soft text-bad", dot: "✕" },
  warn: { label: "告警", cls: "border-warn/30 bg-warn-soft text-warn", dot: "⚠️" },
};

// 层 → 归约徽章 + 公式模板(实值代入,UI 零自算:只拼接后端返回值字符串)
const LAYERS = [
  {
    name: "输入绑定/防重放",
    badges: [BADGES.BIND, BADGES.REPLAY],
    formula: (r, ob) => [
      "层1 公式:input_hash = H(JCS(出站包前映像)) ⊕ nonce ⊕ timestamp",
      `input_hash = ${r?.input_hash || ob?.input_hash || "(…)"}`,
      `nonce = ${ob?.nonce || "(…)"} · timestamp = ${ob?.timestamp || "(…)"}`,
    ],
  },
  {
    name: "模型身份",
    badges: [BADGES.AUDIT],
    formula: (r, ob) => [
      "层2 公式:Ed25519.Verify(auditor_pk, model_cert) → ok",
      `model_cert = ${String(r?.model_cert || "(…)").slice(0, 120)}…`,
      "(证书文本取后端 model_cert 原值,验签在后端完成)",
    ],
  },
  {
    name: "响应完整性",
    badges: [BADGES.SIGN],
    formula: (r, ob) => [
      "层3 公式:response_hash = H(output ‖ input_hash ‖ model_cert ‖ nonce ‖ timestamp)",
      `response_hash = ${r?.response_hash || "(…)"}`,
      `Ed25519.Verify(provider_pk, response_hash) → ${r?.verification?.find((v) => v.layer === "响应完整性")?.ok ? "true" : "false"}`,
    ],
  },
  {
    name: "可审计日志",
    badges: [BADGES.AUDIT, BADGES.BIND],
    formula: (r, ob) => [
      '层4 公式:entry.hash = H({"d":"CG/LOG/v2","ty","p","ts","prev"})(JCS 域分隔)',
      `payload_digest(QUERY) = ${r?.input_hash || "(…)"}`,
      "链验证在 /api/logs 统一执行(chain_valid)",
    ],
  },
];

// 步骤④ 四层验证:逐项打勾(动效白名单「四层打勾」)+ 五态状态机 + 还原四行
export default function Step4Verify({ response }) {
  const [states, setStates] = useState(["idle", "idle", "idle", "idle"]);
  const verification = response?.verification || [];
  const ob = response?.outbound;

  // 逐层打勾:验证中(蓝)→ 通过绿/失败红,层间 350ms 错峰(仅呈现动画,结果以后端为准)
  useEffect(() => {
    if (!response) {
      setStates(["idle", "idle", "idle", "idle"]);
      return;
    }
    const timers = [];
    const next = ["checking", "checking", "checking", "checking"];
    setStates(next);
    LAYERS.forEach((_, i) => {
      timers.push(
        setTimeout(() => {
          const v = verification[i];
          setStates((s) => {
            const arr = [...s];
            arr[i] = !v ? "warn" : v.ok ? "pass" : "fail";
            return arr;
          });
        }, 350 * (i + 1))
      );
    });
    return () => timers.forEach(clearTimeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [response]);

  const globalState = !response
    ? "idle"
    : states.includes("checking")
      ? "checking"
      : response.gateway_rejected
        ? "warn"
        : states.includes("fail")
          ? "fail"
          : states.every((s) => s === "pass")
            ? "pass"
            : "warn";
  const g = STATE_UI[globalState];

  return (
    <div className="space-y-4">
      {/* 全局状态机 */}
      <div className={`rounded-xl border px-4 py-3 flex items-center gap-3 flex-wrap ${g.cls}`}>
        <span className="text-[15px]">{g.dot}</span>
        <span className="text-[14px] font-semibold">四层验证状态机:{g.label}</span>
        <span className="text-[11px] opacity-80">正常灰 → 验证中蓝 → 通过绿 / 失败红 / 告警橙</span>
        {response?.gateway_rejected && (
          <span className="px-2 py-0.5 rounded-full border border-warn/30 bg-warn-soft text-warn text-[11px] font-medium">
            gateway_rejected:{response.rejection_reason}
          </span>
        )}
      </div>

      {/* 四层逐项 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {LAYERS.map((L, i) => {
          const v = verification[i];
          const st = STATE_UI[states[i]];
          return (
            <div key={L.name} className={`rounded-xl border px-4 py-3 transition-colors duration-300 ${st.cls}`}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[14px]">{st.dot}</span>
                <span className="text-[13px] font-semibold">层 {i + 1}:{L.name}</span>
                {L.badges.map((b) => (
                  <span key={b} className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[10px] font-medium">
                    {b}
                  </span>
                ))}
                <span className="ml-auto text-[11px] font-medium">{st.label}</span>
              </div>
              <div className="mt-2 space-y-1 mono text-[10px] text-ink-soft break-all">
                {L.formula(response, ob).map((line, j) => (
                  <div key={j}>{line}</div>
                ))}
              </div>
              <div className="mt-2 text-[11px] text-ink">
                {v ? v.detail : response ? "(该层无结果)" : "等待步骤① 发送…"}
              </div>
            </div>
          );
        })}
      </div>

      {/* 还原预览四行分列(🔒 还原仅本地) */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">还原预览(四行分列)</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            🔒 还原仅本地
          </span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.PRF}
          </span>
          <span className="text-[11px] text-ink-faint">映射表经 AES-GCM 封块,解封与还原都在本地代理完成,不出网</span>
        </div>
        <div className="p-4 space-y-2">
          {[
            ["① 出站 output(令牌形态)", response?.output || "(…)", "text-ink"],
            ["② 本地还原 restored_output", response?.restored_output || "(…)", "text-vault-700"],
            [
              "③ 可读通道文件(脱敏正文)",
              (ob?.file_payloads || []).filter((f) => f.content_tier === "readable").map((f) => f.redacted_content || "(空)").join(" ‖ ") || "(无)",
              "text-ink-soft",
            ],
            [
              "④ 存证通道承诺(不可读)",
              (ob?.file_payloads || []).filter((f) => f.content_tier === "evidence").map((f) => `file_hash=${f.file_hash}`).join(" ‖ ") || "(无)",
              "text-crypto-violet",
            ],
          ].map(([label, value, cls]) => (
            <div key={label} className="rounded-lg border border-line bg-paper px-3 py-2">
              <div className="text-[10px] text-ink-faint">{label}</div>
              <div className={`mono text-[11px] break-all ${cls}`}>{String(value)}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
