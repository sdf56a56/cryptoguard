import { useState } from "react";
import PreimagePanel from "./PreimagePanel.jsx";
import { BADGES } from "./badges.js";

// 步骤③ 出站包:Wireshark 风格收据块 + 前映像面板 + 明文/出站 Diff 切换 + nonce 时间窗
// UI 零自算:全部字段原样渲染后端 query2 响应,前端不生成任何哈希/签名。
export default function Step3Outbound({ response, originalText }) {
  const [showPlain, setShowPlain] = useState(false);
  const ob = response?.outbound;

  if (!response || !ob) {
    return (
      <div className="rounded-xl border border-line bg-surface p-8 text-center text-ink-soft text-[13px]">
        步骤① 发送后,这里显示 CG/2.0 出站包收据(后端字段原样渲染,前端零自算)
      </div>
    );
  }

  const files = ob.file_payloads || [];

  return (
    <div className="space-y-4">
      {/* Wireshark 风格收据块 */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">出站包收据(POST /api/proxy/query2)</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.BIND}
          </span>
          <span className="px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[11px] font-medium">
            {BADGES.REPLAY}
          </span>
          <span className={`ml-auto px-2 py-0.5 rounded-full border text-[11px] font-medium ${
            response.status === "verified"
              ? "border-ok/25 bg-ok-soft text-ok"
              : "border-bad/25 bg-bad-soft text-bad"
          }`}>
            status = {response.status}
          </span>
        </div>
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1.5 mono text-[11px]">
          {[
            ["schema_version", ob.schema_version],
            ["request_id", response.request_id],
            ["session_id", ob.session_id],
            ["token_root", ob.token_root],
            ["input_hash", ob.input_hash],
            ["nonce", ob.nonce],
            ["timestamp", ob.timestamp],
            ["mock_sleep_ms", response.mock_sleep_ms],
          ].map(([k, v]) => (
            <div key={k} className="flex items-start gap-2">
              <span className="text-ink-faint w-32 shrink-0">{k}</span>
              <span className="text-ink break-all">{String(v ?? "(空)")}</span>
            </div>
          ))}
        </div>
        {/* 文件载荷(双通道) */}
        {files.length > 0 && (
          <div className="px-4 pb-4 space-y-2">
            <div className="text-[11px] font-semibold text-ink-soft">file_payloads(双通道)</div>
            {files.map((f, i) => (
              <div key={i} className="rounded-lg border border-line bg-paper px-3 py-2 mono text-[10px] space-y-0.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-ink text-[11px] font-semibold">{f.filename_token}</span>
                  <span className={`px-2 py-0.5 rounded-full border text-[10px] font-medium ${
                    f.content_tier === "readable"
                      ? "bg-vault-50 text-vault-700 border-vault-200"
                      : "bg-crypto-violetSoft text-crypto-violet border-crypto-violet/25"
                  }`}>
                    {f.content_tier === "readable" ? "📄 可读通道" : "🔒 存证通道(模型不可读)"}
                  </span>
                  <span className="px-1.5 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[10px]">
                    {BADGES.FILE}
                  </span>
                </div>
                <div className="text-ink-faint break-all">file_ref = {f.file_ref} · file_hash = {f.file_hash}</div>
                {f.file_content_hash && (
                  <div className="text-ink-faint break-all">file_content_hash = {f.file_content_hash}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 前映像面板(R8:canonical_preimage 取 outbound.canonical_preimage,前端不生成) */}
      <PreimagePanel canonicalString={ob.canonical_preimage} inputHash={ob.input_hash} />

      {/* 明文 / 出站 Diff 切换(两栏 original_input vs redacted_text) */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">明文 / 出站 Diff</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            🔒 出站无明文
          </span>
          <button
            onClick={() => setShowPlain((v) => !v)}
            className="ml-auto px-3 py-1 rounded-lg border border-line bg-paper text-[11px] text-ink-soft hover:border-vault-300 hover:text-vault-700"
          >
            {showPlain ? "隐藏明文对照" : "显示明文对照(仅本地)"}
          </button>
        </div>
        <div className={`p-4 grid gap-3 ${showPlain ? "grid-cols-1 md:grid-cols-2" : "grid-cols-1"}`}>
          {showPlain && (
            <div className="rounded-lg border border-warn/30 bg-warn-soft/40 px-3 py-2">
              <div className="text-[11px] font-semibold text-warn mb-1">original_input(明文,仅本地)</div>
              <div className="text-[12px] text-ink leading-6 break-all">{originalText || "(空)"}</div>
            </div>
          )}
          <div className="rounded-lg border border-vault-200 bg-vault-50/40 px-3 py-2">
            <div className="text-[11px] font-semibold text-vault-700 mb-1">redacted_text(出站,已令牌化)</div>
            <div className="text-[12px] text-ink leading-6 break-all">{ob.redacted_text || "(空)"}</div>
          </div>
        </div>
      </div>

      {/* nonce / 时间窗可视化(⏱ 5 分钟防重放窗) */}
      <div className="rounded-xl border border-line bg-surface px-4 py-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">nonce / 时间窗</span>
          <span className="px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[11px] font-medium">
            {BADGES.REPLAY}
          </span>
          <span className="text-[11px] text-ink-faint">5 分钟窗 + nonce 一次性,过期即拒(层 1)</span>
        </div>
        <div className="mt-2 space-y-2">
          <div className="flex items-center gap-2 mono text-[10px] text-ink-faint flex-wrap">
            <span>issue {ob.timestamp}</span>
            <span>→</span>
            <span>+5min 过期</span>
            <span className="ml-auto">nonce = {ob.nonce}</span>
          </div>
          {/* 静态时间窗示意(无模拟动画,数值为后端 timestamp 文本) */}
          <div className="h-2.5 rounded-full bg-paper border border-line overflow-hidden flex">
            <div className="h-full bg-vault-400 w-[85%]" title="有效窗内" />
            <div className="h-full bg-bad/60 w-[15%]" title="过期拒绝" />
          </div>
          <div className="flex justify-between text-[10px] text-ink-faint">
            <span>⏱ 有效窗(5 分钟)</span>
            <span>过期 → 层 1 拒绝</span>
          </div>
        </div>
      </div>
    </div>
  );
}
