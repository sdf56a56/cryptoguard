import { useEffect, useReducer, useState } from "react";
import StepNav from "./StepNav.jsx";
import TimingBar from "./TimingBar.jsx";
import AppendixDrawer from "./AppendixDrawer.jsx";
import Step1Input from "./Step1Input.jsx";
import Step2Tokens from "./Step2Tokens.jsx";
import { api, fileToBase64 } from "../api.js";
import { BADGES } from "./badges.js";

// 六步状态机(useReducer):step 1..6 + attackSnapshot(攻击沙箱命中标志)
const initialState = { step: 1, attackSnapshot: false };

function reducer(state, action) {
  switch (action.type) {
    case "GOTO":
      return { ...state, step: Math.min(6, Math.max(1, action.step)) };
    case "NEXT":
      return { ...state, step: Math.min(6, state.step + 1) };
    case "PREV":
      return { ...state, step: Math.max(1, state.step - 1) };
    case "ATTACK_ON":
      return { ...state, attackSnapshot: true };
    case "ATTACK_OFF":
      return { ...state, attackSnapshot: false };
    default:
      return state;
  }
}

// 威胁模型四角色(常驻横幅,chrome)
const ROLES = ["👤 用户", "🖥 本地代理 CryptoGuard", "☁️ 大模型服务商", "🛡 审计机构"];
// 明确不承诺 ×3(spec §7 摘选)
const DISCLAIMERS = [
  "不证明大模型内部实际计算了什么(非 zkML)",
  "不承诺防服务商主动调包(除非加 TEE)",
  "可读通道保密性 = 检测召回率的函数,漏检即泄露",
];

const SAMPLE =
  "患者张伟,男,45岁,身份证110101199003077777,手机13800138000,邮箱zhangwei@example.com,住址北京市海淀区中关村街道1号。诊断:高血压,参与天枢计划临床试验。";

export default function Console() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // 跨步骤共享:输入 + 检测预览 + 文件 + 最近一次 query2 响应
  const [text, setText] = useState(SAMPLE);
  const [scenario, setScenario] = useState("medical");
  const [detect, setDetect] = useState(null);
  const [fileItems, setFileItems] = useState([]);
  const [response, setResponse] = useState(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(null);
  const [ff1Degraded, setFf1Degraded] = useState(false);

  // /api/perf:FF1 降级横幅位(后端当前未暴露 ff1_degraded 字段 → 横幅隐藏)
  useEffect(() => {
    api.perf()
      .then((p) => {
        const flag = p?.ff1_degraded ?? p?.FF1_DEGRADED ?? p?.flags?.FF1_DEGRADED;
        setFf1Degraded(Boolean(flag));
      })
      .catch(() => setFf1Degraded(false));
  }, []);

  // 步骤① 发送 → POST /api/proxy/query2 → 响应驱动②–⑥
  const handleSend = async (overrides) => {
    setSending(true);
    setError(null);
    try {
      let files;
      if (fileItems.length) {
        files = await Promise.all(
          fileItems
            .filter((it) => !it.info?.error)
            .map(async (it) => ({
              filename: it.file.name,
              content_b64: await fileToBase64(it.file),
            }))
        );
      }
      const data = await api.query2({
        schema_version: "CG/2.0",
        text,
        scenario,
        overrides: overrides?.length ? overrides : undefined,
        files: files?.length ? files : undefined,
      });
      setResponse(data);
      dispatch({ type: "GOTO", step: 2 });
    } catch (e) {
      setError(String(e?.message || e));
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="min-h-screen bg-paper text-ink flex flex-col">
      {/* 顶部常驻横幅:威胁模型四角色 | 明确不承诺 ×3 | [附录抽屉▾] */}
      <header className="border-b border-line bg-surface px-6 py-3">
        <div className="flex items-start gap-4 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-semibold text-ink-soft">威胁模型</span>
            {ROLES.map((r, i) => (
              <span key={r} className="flex items-center gap-1">
                <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
                  {r}
                </span>
                {i < ROLES.length - 1 && <span className="text-ink-faint text-[10px]">⇄</span>}
              </span>
            ))}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-semibold text-bad">明确不承诺</span>
            {DISCLAIMERS.map((d) => (
              <span
                key={d}
                className="px-2 py-0.5 rounded-full border border-bad/25 bg-bad-soft text-bad text-[11px]"
              >
                ✕ {d}
              </span>
            ))}
          </div>
          <button
            onClick={() => setDrawerOpen((v) => !v)}
            className="ml-auto px-3 py-1.5 rounded-lg border border-line bg-paper text-[12px] font-medium text-ink-soft hover:border-vault-300 hover:text-vault-700"
          >
            附录抽屉 ▾
          </button>
        </div>
        <div className="mt-2 flex items-center gap-2 flex-wrap">
          <span className="display font-bold text-ink text-[15px]">CryptoGuard 六步控制台</span>
          <span className="text-[11px] text-ink-faint">CG/2.0 · 单线路由 · UI 零自算</span>
          <span className="px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[11px] font-medium">
            {BADGES.NLP}
          </span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.BIND}
          </span>
          {state.attackSnapshot && (
            <span className="px-2 py-0.5 rounded-full border border-bad/25 bg-bad-soft text-bad text-[11px] font-medium alert-pulse">
              沙箱快照命中(主链未污染)
            </span>
          )}
        </div>
      </header>

      <StepNav step={state.step} onGo={(step) => dispatch({ type: "GOTO", step })} />

      {/* 当前步骤视图(单一活动区) */}
      <main className="flex-1 overflow-y-auto px-6 py-5">
        {error && (
          <div className="mb-4 rounded-xl border border-bad/40 bg-bad-soft px-4 py-3 text-[13px] text-bad">
            请求失败:{error}
          </div>
        )}
        {state.step === 1 && (
          <Step1Input
            text={text}
            onTextChange={setText}
            scenario={scenario}
            onScenarioChange={setScenario}
            detect={detect}
            onDetect={setDetect}
            fileItems={fileItems}
            onFilesChange={setFileItems}
            onSend={handleSend}
            sending={sending}
          />
        )}
        {state.step === 2 && (
          <Step2Tokens
            response={response}
            detect={detect}
            fileItems={fileItems}
            ff1Degraded={ff1Degraded}
          />
        )}
        {state.step >= 3 && (
          <div className="rounded-xl border border-line bg-surface p-8 text-center text-ink-soft text-[13px]">
            步骤 {state.step} 视图 —— 后续任务填充(③出站包 ④四层验证 ⑤攻击注入 ⑥审计链)
          </div>
        )}
      </main>

      <TimingBar
        pipeline={response?.pipeline}
        totalMs={response?.total_ms}
        mockSleepMs={response?.mock_sleep_ms}
      />

      <AppendixDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} />
    </div>
  );
}
