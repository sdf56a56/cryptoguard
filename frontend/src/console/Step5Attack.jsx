import { useRef, useState } from "react";
import { api } from "../api.js";
import { BADGES } from "./badges.js";

// 九攻击 + 一键重置(裁定 R9:按钮总数 10,顺序 = spec §4.2 表)
const ATTACKS = [
  { key: "tamper", n: "1", label: "篡改响应", expect: "层 3 响应完整性", badge: BADGES.SIGN },
  { key: "replay", n: "2", label: "重放", expect: "层 1 nonce/时间窗", badge: BADGES.REPLAY },
  { key: "forge_cert", n: "3", label: "伪造 cert", expect: "层 2 模型身份", badge: BADGES.AUDIT },
  { key: "tamper_log", n: "4", label: "篡改日志", expect: "链断 + Merkle 路径失败", badge: BADGES.BIND },
  { key: "repudiate_user", n: "5a", label: "用户诬告", expect: "input_hash 重算失配", badge: `${BADGES.BIND} 可复算` },
  { key: "repudiate_provider", n: "5b", label: "服务商抵赖", expect: "签名覆盖的 input_hash 与链上一致", badge: BADGES.SIGN },
  { key: "swap_token", n: "6", label: "令牌张冠李戴", expect: "token_root 失配", badge: BADGES.BIND },
  { key: "swap_file", n: "7", label: "文件内容偷换", expect: "file_content_hash 失配", badge: BADGES.FILE },
  { key: "bad_directive", n: "8", label: "注入非法令牌", expect: "计算网关白名单拒 → COMPUTE_GATE 入链", badge: BADGES.USER },
];

// 失败传播链路(断点沿协议链回溯,layer_hit 命中节点先红,前序节点依次转红)
const CHAIN_NODES = ["输入绑定/防重放", "模型身份", "响应完整性", "可审计日志", "计算网关"];

function hitIndex(layerHit) {
  const i = CHAIN_NODES.findIndex((n) => String(layerHit || "").includes(n.replace("/防重放", "")) || n.includes(String(layerHit || "")));
  return i >= 0 ? i : 3;
}

// 步骤⑤ 攻击注入(沙箱化):9 攻击 + reset,失败传播动画,话术卡取后端 detail
export default function Step5Attack({ onSandboxFlag }) {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(null);
  const [confirmKey, setConfirmKey] = useState(null);
  const [propagated, setPropagated] = useState(-1);
  const timerRef = useRef([]);

  const clearTimers = () => {
    timerRef.current.forEach(clearTimeout);
    timerRef.current = [];
  };

  const inject = async (atk) => {
    setConfirmKey(null);
    setBusy(atk.key);
    clearTimers();
    setPropagated(-1);
    try {
      const r = await api.attackInject(atk.key);
      setResult(r);
      onSandboxFlag?.(true);
      // 失败传播:命中节点先红,再沿链向前逐节点转红(CSS transition,动效白名单)
      const hi = hitIndex(r.layer_hit);
      for (let k = 0; k <= hi; k++) {
        timerRef.current.push(setTimeout(() => setPropagated(hi - k), 180 * k));
      }
    } catch (e) {
      setResult({ attack: atk.key, ok: false, layer_hit: "(请求失败)", detail: String(e?.message || e) });
      onSandboxFlag?.(true);
    } finally {
      setBusy(null);
    }
  };

  const reset = async () => {
    clearTimers();
    setBusy("reset");
    try {
      await api.attackReset();
      setResult(null);
      setPropagated(-1);
      onSandboxFlag?.(false);
    } catch (e) {
      setResult({ attack: "reset", ok: false, layer_hit: "(请求失败)", detail: String(e?.message || e) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4">
      {/* 沙箱声明 */}
      <div className="rounded-xl border border-warn/30 bg-warn-soft/50 px-4 py-3 flex items-center gap-2 flex-wrap">
        <span className="text-[13px] font-semibold text-warn">攻击沙箱(SEC-ISO)</span>
        <span className="text-[11px] text-ink-soft">
          攻击写入沙箱快照,不影响主链 —— 8 攻击全注入后主链 verify() 仍为真;一键重置恢复快照。
        </span>
      </div>

      {/* 9 攻击按钮 + 1 重置 */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">攻击注入(9 攻击 + 一键重置)</span>
          <span className="text-[11px] text-ink-faint">红色按钮前置确认后注入,结果由后端沙箱真实验证产生</span>
        </div>
        <div className="p-4 flex items-start gap-2 flex-wrap">
          {ATTACKS.map((a) => (
            <div key={a.key} className="relative">
              {confirmKey === a.key ? (
                <div className="rounded-lg border border-bad/40 bg-bad-soft p-2 w-56">
                  <div className="text-[11px] text-bad font-medium">
                    攻击写入沙箱快照,不影响主链。确认注入「{a.label}」?
                  </div>
                  <div className="mt-2 flex gap-2">
                    <button
                      onClick={() => inject(a)}
                      disabled={busy != null}
                      className="px-2.5 py-1 rounded-lg bg-bad text-white text-[11px] font-medium disabled:opacity-50"
                    >
                      确认注入
                    </button>
                    <button
                      onClick={() => setConfirmKey(null)}
                      className="px-2.5 py-1 rounded-lg border border-line bg-paper text-[11px] text-ink-soft"
                    >
                      取消
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmKey(a.key)}
                  disabled={busy != null}
                  title={`预期拦截:${a.expect}`}
                  className="px-3 py-2 rounded-lg border border-bad/40 bg-bad-soft text-bad text-[12px] font-semibold hover:bg-bad hover:text-white transition-colors disabled:opacity-50"
                >
                  <span className="mono text-[10px] opacity-70 mr-1">{a.n}</span>
                  {a.label}
                  <span className="ml-1.5 text-[10px] opacity-80">{a.badge}</span>
                </button>
              )}
            </div>
          ))}
          <button
            onClick={reset}
            disabled={busy != null}
            className="px-3 py-2 rounded-lg border border-ok/40 bg-ok-soft text-ok text-[12px] font-semibold hover:bg-ok hover:text-white transition-colors disabled:opacity-50"
          >
            ↺ 一键重置(恢复沙箱快照)
          </button>
        </div>
      </div>

      {/* 失败传播(断点沿协议链回溯,后端 layer_hit 驱动) */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <span className="text-[13px] font-semibold text-ink">失败传播(协议链回溯)</span>
          <span className="text-[11px] text-ink-faint">命中节点先红,前序节点依次转红 —— 断点定位</span>
        </div>
        <div className="p-4 flex items-center gap-1 flex-wrap">
          {CHAIN_NODES.map((n, i) => {
            const red = result && i <= propagated;
            return (
              <div key={n} className="flex items-center gap-1">
                <span
                  className={`px-2.5 py-1.5 rounded-lg border text-[11px] font-medium transition-colors duration-500 ${
                    red ? "border-bad bg-bad text-white alert-pulse" : "border-line bg-paper text-ink-soft"
                  }`}
                  style={red ? { transitionDelay: `${i * 60}ms` } : undefined}
                >
                  {n}
                </span>
                {i < CHAIN_NODES.length - 1 && <span className={red ? "text-bad" : "text-ink-faint text-[10px]"}>→</span>}
              </div>
            );
          })}
        </div>
      </div>

      {/* 结果红闪 + 话术卡(文案取后端 attack_result.detail) */}
      {result && (
        <div className="rounded-xl border border-bad/40 bg-bad-soft alert-pulse">
          <div className="px-4 py-2.5 border-b border-bad/25 flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-semibold text-bad">攻击注入结果(沙箱)</span>
            <span className="mono text-[11px] text-bad">attack = {result.attack}</span>
            <span className="px-2 py-0.5 rounded-full border border-bad/30 bg-paper text-bad text-[11px] font-medium">
              layer_hit = {result.layer_hit}
            </span>
            <span className="px-2 py-0.5 rounded-full border border-bad/30 bg-paper text-bad text-[11px] font-medium">
              ok = {String(result.ok)}
            </span>
          </div>
          {/* 话术卡(答辩台词,后端 detail 原文) */}
          <div className="px-4 py-3">
            <div className="text-[11px] font-semibold text-bad mb-1">话术卡(答辩台词 · 后端 detail 原文)</div>
            <div className="rounded-lg border border-bad/25 bg-paper px-3 py-2 text-[12px] text-ink leading-6">
              {result.detail}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
