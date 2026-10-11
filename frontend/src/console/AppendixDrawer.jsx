import { useEffect, useState } from "react";
import { api } from "../api.js";
import { BADGES } from "./badges.js";

// 合规映射(静态表,spec §4.0 抽屉「合规映射」)
const COMPLIANCE = [
  ["HIPAA §164.312(a)(1)", "访问控制", "CP-ABE 授权树解封映射表(5 属性策略)"],
  ["HIPAA §164.312(c)(1)", "完整性", "file_content_hash 承诺 + 哈希链 + Merkle 打包"],
  ["HIPAA §164.312(b)", "审计控制", "USER_OVERRIDE / QUERY / FILE_COMMIT / COMPUTE_GATE 入链"],
  ["HIPAA §164.312(e)(1)", "传输安全", "出站零明文(令牌化)+ Ed25519 响应签名"],
  ["PCI-DSS 3.4", "持卡人数据掩码", "T1 伪名 / T2 FF1 格式保留(泄漏显式声明)"],
  ["PCI-DSS 4.1", "强加密传输", "TLS 部署承诺 + 响应完整性签名(演示环境为本地 Mock)"],
  ["PCI-DSS 8.7", "密钥/凭证访问", "AES-GCM 映射表封块 + 会话密钥隔离"],
  ["PCI-DSS 10.2", "审计日志", "追加式哈希链(JCS 域分隔)+ Merkle 打包触发器"],
];

// CryptoLab 可选增强演示(不在主链路,调旧接口)
function CryptoLabSection() {
  const [keyword, setKeyword] = useState("张伟");
  const [values, setValues] = useState("3,7,11,15");
  const [sse, setSse] = useState(null);
  const [he, setHe] = useState(null);
  const [zkp, setZkp] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn, setter) => {
    setBusy(true);
    try {
      setter(await fn());
    } catch (e) {
      setter({ error: String(e?.message || e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-warn/30 bg-warn-soft/50 px-3 py-2 text-[11px] text-warn font-medium">
        可选增强,不在主链路 —— 仅演示扩展能力,不影响六步协议叙事与性能预算。
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[10px] font-medium">
          ⚠️ SSE 访问模式泄漏沿用既有声明
        </span>
        <span className="px-2 py-0.5 rounded-full border border-crypto-violet/25 bg-crypto-violetSoft text-crypto-violet text-[10px] font-medium">
          {BADGES.DCR}
        </span>
      </div>
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            className="flex-1 px-2 py-1 rounded-lg border border-line bg-paper text-[11px] mono"
            placeholder="SSE 关键词"
          />
          <button
            onClick={() => run(() => api.sseSearch(keyword), setSse)}
            disabled={busy}
            className="px-2.5 py-1 rounded-lg border border-line bg-surface text-[11px] text-ink-soft hover:border-vault-300 disabled:opacity-50"
          >
            SSE 搜索
          </button>
        </div>
        {sse && (
          <pre className="max-h-28 overflow-auto mono text-[10px] text-ink-soft bg-paper border border-line rounded-lg p-2 whitespace-pre-wrap break-all">
{JSON.stringify(sse, null, 2)}
          </pre>
        )}
        <div className="flex items-center gap-2">
          <input
            value={values}
            onChange={(e) => setValues(e.target.value)}
            className="flex-1 px-2 py-1 rounded-lg border border-line bg-paper text-[11px] mono"
            placeholder="Paillier 明文值(逗号分隔)"
          />
          <button
            onClick={() =>
              run(
                () => api.heStats(values.split(",").map((v) => Number(v.trim())).filter((n) => !Number.isNaN(n))),
                setHe
              )
            }
            disabled={busy}
            className="px-2.5 py-1 rounded-lg border border-line bg-surface text-[11px] text-ink-soft hover:border-vault-300 disabled:opacity-50"
          >
            同态统计
          </button>
        </div>
        {he && (
          <pre className="max-h-28 overflow-auto mono text-[10px] text-ink-soft bg-paper border border-line rounded-lg p-2 whitespace-pre-wrap break-all">
{JSON.stringify(he, null, 2)}
          </pre>
        )}
        <button
          onClick={() => run(() => api.zkpInfo(), setZkp)}
          disabled={busy}
          className="px-2.5 py-1 rounded-lg border border-line bg-surface text-[11px] text-ink-soft hover:border-vault-300 disabled:opacity-50"
        >
          ZKP 演示(GET /api/zkp/info)
        </button>
        {zkp && (
          <pre className="max-h-28 overflow-auto mono text-[10px] text-ink-soft bg-paper border border-line rounded-lg p-2 whitespace-pre-wrap break-all">
{JSON.stringify(zkp, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}

// 性能实测(/api/perf + 降级横幅位)
function PerfSection({ open }) {
  const [perf, setPerf] = useState(null);
  const [ff1Degraded, setFf1Degraded] = useState(false);

  useEffect(() => {
    if (!open) return;
    api.perf()
      .then((p) => {
        setPerf(p);
        const flag = p?.ff1_degraded ?? p?.FF1_DEGRADED ?? p?.flags?.FF1_DEGRADED;
        setFf1Degraded(Boolean(flag));
      })
      .catch(() => setPerf(null));
  }, [open]);

  return (
    <div className="space-y-2">
      {/* 降级横幅位(后端当前未暴露 ff1_degraded → 横幅隐藏) */}
      {ff1Degraded ? (
        <div className="rounded-lg border border-warn/40 bg-warn-soft px-3 py-2 text-[11px] text-warn font-semibold">
          ⚠️ FF1 已降级为格式校验演示,演示令牌 ≤5 个
        </div>
      ) : (
        <div className="rounded-lg border border-line bg-paper px-3 py-2 text-[10px] text-ink-faint">
          降级横幅位:FF1 未触发降级(/api/perf 未暴露 ff1_degraded 字段 → 按未降级处理,横幅隐藏)
        </div>
      )}
      <table className="w-full text-[11px]">
        <thead>
          <tr className="text-left text-ink-faint border-b border-line">
            <th className="py-1 font-medium">操作</th>
            <th className="py-1 font-medium">目标单价(ms)</th>
          </tr>
        </thead>
        <tbody>
          {(perf?.targets || []).map((t) => (
            <tr key={t.op} className="border-b border-line/60">
              <td className="py-1 text-ink">{t.op}</td>
              <td className="py-1 mono text-vault-700">{Number(t.target_ms).toFixed(2)}</td>
            </tr>
          ))}
          {!perf && (
            <tr>
              <td className="py-2 text-ink-faint" colSpan={2}>
                (加载中…)
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <div className="text-[10px] text-ink-faint">
        端到端 P50/P95 与吞吐以压测报告为准(§5.3 测试环境:Ryzen 7 7735H,多 worker + 线程池);
        密码学核心合计目标 &lt;20ms。FF1 单价以 PERF-FF1-1 实测校准,超预算即降级并常驻横幅。
      </div>
    </div>
  );
}

// 附录抽屉(§4.0 一抽屉):CryptoLab 可选增强 / 性能实测 / 合规映射
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
            <div className="px-4 pb-4">
              <CryptoLabSection />
            </div>
          </details>
          <details className="rounded-xl border border-line bg-paper">
            <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink">
              📊 性能实测(预算对照 + 降级横幅位)
            </summary>
            <div className="px-4 pb-4">
              <PerfSection open={open} />
            </div>
          </details>
          <details className="rounded-xl border border-line bg-paper">
            <summary className="px-4 py-3 cursor-pointer text-[13px] font-semibold text-ink">
              📜 合规映射(HIPAA / PCI-DSS)
            </summary>
            <div className="px-4 pb-4">
              <table className="w-full text-[10px]">
                <thead>
                  <tr className="text-left text-ink-faint border-b border-line">
                    <th className="py-1 pr-2 font-medium">条款</th>
                    <th className="py-1 pr-2 font-medium">要求</th>
                    <th className="py-1 font-medium">CryptoGuard 对应机制</th>
                  </tr>
                </thead>
                <tbody>
                  {COMPLIANCE.map(([clause, req, mech]) => (
                    <tr key={clause} className="border-b border-line/60 align-top">
                      <td className="py-1 pr-2 mono text-vault-700 whitespace-nowrap">{clause}</td>
                      <td className="py-1 pr-2 text-ink">{req}</td>
                      <td className="py-1 text-ink-soft">{mech}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="mt-2 text-[10px] text-ink-faint">
                静态映射表(答辩口径):演示系统不构成合规认证,仅展示机制覆盖关系。
              </div>
            </div>
          </details>
        </div>
      </aside>
    </>
  );
}
