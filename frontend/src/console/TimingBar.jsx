import { formatMs, isMockStep } from "./timing.js";
import { BADGES } from "./badges.js";
import { Badge } from "../components/ui.jsx";

// 计时条(底部常驻):pipeline 各段 duration_ms 原样渲染,2 位小数;
// mock 段如实标注「Mock 模拟延迟」,不做模拟动画(动效白名单外)。
export default function TimingBar({ pipeline, totalMs, mockSleepMs }) {
  const steps = Array.isArray(pipeline) ? pipeline : [];
  return (
    <footer className="border-t border-line bg-surface px-6 py-3">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-[11px] font-semibold text-ink-soft shrink-0">
          计时条(真实时间戳,无模拟动画)
        </span>
        <Badge color="warn">{BADGES.REPLAY}</Badge>
        {steps.length === 0 && (
          <span className="text-[11px] text-ink-faint">
            运行查询后按 pipeline 真实值显示各段耗时
          </span>
        )}
        {steps.map((st, i) => {
          const mock = isMockStep(st);
          return (
            <div
              key={i}
              className="flex items-center gap-1.5 rounded-lg border border-line bg-paper px-2.5 py-1"
              title={st.step}
            >
              <span className="text-[10px] text-ink-faint mono">{i + 1}</span>
              <span className="text-[11px] text-ink">{st.step}</span>
              <span
                className={`mono text-[11px] ${mock ? "text-warn font-semibold" : "text-vault-700"}`}
              >
                {formatMs(st.duration_ms, mock)}
              </span>
            </div>
          );
        })}
        {totalMs != null && (
          <div className="flex items-center gap-1.5 rounded-lg border border-vault-200 bg-vault-50 px-2.5 py-1 ml-auto">
            <span className="text-[11px] text-vault-700 font-semibold">端到端</span>
            <span className="mono text-[11px] text-vault-700 font-semibold">
              {formatMs(totalMs)}
            </span>
          </div>
        )}
        {mockSleepMs != null && (
          <div className="flex items-center gap-1.5 rounded-lg border border-warn/30 bg-warn-soft px-2.5 py-1">
            <span className="text-[11px] text-warn font-semibold">
              mock_sleep_ms {formatMs(mockSleepMs, true)}
            </span>
          </div>
        )}
      </div>
    </footer>
  );
}
