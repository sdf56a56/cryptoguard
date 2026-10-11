export const STEPS = [
  { n: 1, label: "①输入" },
  { n: 2, label: "②令牌化" },
  { n: 3, label: "③出站包" },
  { n: 4, label: "④四层验证" },
  { n: 5, label: "⑤攻击注入" },
  { n: 6, label: "⑥审计链" },
];

// 六步导航(答辩不切页,单路由内步进)
export default function StepNav({ step, onGo }) {
  return (
    <nav className="flex items-center gap-1 px-6 py-2 border-b border-line bg-surface overflow-x-auto">
      {STEPS.map((s, i) => (
        <div key={s.n} className="flex items-center gap-1">
          <button
            onClick={() => onGo(s.n)}
            className={`px-3 py-1.5 rounded-lg text-[13px] font-medium whitespace-nowrap transition-colors ${
              step === s.n
                ? "bg-vault-500 text-white shadow-[0_2px_8px_-2px_rgba(67,97,238,0.5)]"
                : step > s.n
                  ? "bg-ok-soft text-ok border border-ok/25"
                  : "bg-paper text-ink-soft border border-line hover:border-vault-300 hover:text-vault-700"
            }`}
          >
            {s.label}
          </button>
          {i < STEPS.length - 1 && (
            <span className={`text-[11px] ${step > s.n ? "text-ok" : "text-ink-faint"}`}>→</span>
          )}
        </div>
      ))}
    </nav>
  );
}
