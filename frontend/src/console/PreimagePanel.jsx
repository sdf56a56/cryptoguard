import { useState } from "react";
import { BADGES } from "./badges.js";

// 前映像面板(Step③ 用,Task 16 先建折叠组件,修正项):
// - <details> 默认折叠、<pre> 可滚动、复制按钮 navigator.clipboard
// - canonicalString 必须是后端返回字段(R8/UI 零自算),前端不生成
// - 展开区第二行展示 input_hash = {inputHash},挂 🔗 抗第二原像 · 可复算
export default function PreimagePanel({ canonicalString, inputHash }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(canonicalString ?? "");
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  return (
    <details className="rounded-xl border border-line bg-paper">
      <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink flex items-center gap-2">
        <span>前映像面板(JCS 规范化串,默认折叠)</span>
        <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
          {BADGES.BIND} · 可复算
        </span>
      </summary>
      <div className="px-4 pb-4 space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-ink-faint">canonical_preimage(后端返回,前端不生成)</span>
          <button
            onClick={copy}
            className="ml-auto px-2.5 py-1 rounded-lg border border-line bg-surface text-[11px] text-ink-soft hover:border-vault-300 hover:text-vault-700"
          >
            {copied ? "已复制 ✓" : "复制"}
          </button>
        </div>
        <pre className="max-h-64 overflow-auto mono text-[11px] text-ink bg-surface border border-line rounded-lg p-3 whitespace-pre-wrap break-all">
{canonicalString ?? "(无)"}
        </pre>
        <div className="mono text-[11px] text-vault-700 bg-vault-50/60 border border-vault-100 rounded-lg px-3 py-2 break-all">
          input_hash = {inputHash ?? "(无)"}
        </div>
      </div>
    </details>
  );
}
