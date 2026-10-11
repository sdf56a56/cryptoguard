import { BADGES } from "./badges.js";

// 附录抽屉(§4.0 一抽屉):三个折叠区 —— CryptoLab 可选增强 / 性能实测 / 合规映射
// 内容组件 Task 17 填充;本骨架先立折叠结构与安全标注。
export default function AppendixDrawer({ open, onClose }) {
  return (
    <>
      {open && (
        <div
          className="fixed inset-0 bg-ink/20 z-40"
          onClick={onClose}
          aria-label="关闭附录抽屉"
        />
      )}
      <aside
        className={`fixed right-0 top-0 h-screen w-[420px] max-w-[92vw] bg-surface border-l border-line z-50 shadow-lift flex flex-col transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="flex items-center gap-2 px-5 py-4 border-b border-line">
          <h2 className="display font-bold text-ink text-[15px]">附录抽屉</h2>
          <span className="text-[11px] text-ink-faint">可选增强 / 实测 / 合规</span>
          <button
            onClick={onClose}
            className="ml-auto px-2.5 py-1 rounded-lg border border-line text-ink-soft text-[12px] hover:border-vault-300 hover:text-vault-700"
          >
            关闭 ✕
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <details className="rounded-xl border border-line bg-paper">
            <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink">
              🧪 CryptoLab(可选增强,不在主链路)
            </summary>
            <div className="px-4 pb-4 text-[12px] text-ink-soft">
              SSE 搜索 / Paillier 同态统计 / ZKP 演示 —— Task 17 接口填充。
              <div className="mt-2">
                <Badge color="warn">{BADGES.DCR}</Badge>
              </div>
            </div>
          </details>
          <details className="rounded-xl border border-line bg-paper">
            <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink">
              📊 性能实测(预算对照 + 降级横幅位)
            </summary>
            <div className="px-4 pb-4 text-[12px] text-ink-soft">
              FF1 单价 / 核心合计 / 端到端 P50·P95 / 吞吐 —— Task 17 从 /api/perf 取值。
            </div>
          </details>
          <details className="rounded-xl border border-line bg-paper">
            <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink">
              📜 合规映射(HIPAA / PCI-DSS)
            </summary>
            <div className="px-4 pb-4 text-[12px] text-ink-soft">
              静态映射表 —— Task 17 填充。
            </div>
          </details>
        </div>
      </aside>
    </>
  );
}

function Badge({ children, color }) {
  const colors = {
    warn: "bg-warn-soft text-warn border-warn/25",
    vault: "bg-vault-50 text-vault-700 border-vault-200",
  };
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-medium ${colors[color] || colors.vault}`}
    >
      {children}
    </span>
  );
}
