import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { BADGES } from "./badges.js";

// entry_type → 四色(spec §4.2 ⑥)
const ENTRY_COLORS = {
  QUERY: "border-vault-200 bg-vault-50 text-vault-700",
  USER_OVERRIDE: "border-warn/30 bg-warn-soft text-warn",
  FILE_COMMIT: "border-crypto-violet/25 bg-crypto-violetSoft text-crypto-violet",
  COMPUTE_GATE: "border-bad/30 bg-bad-soft text-bad",
};

const ENTRY_BADGE = {
  QUERY: BADGES.BIND,
  USER_OVERRIDE: BADGES.USER,
  FILE_COMMIT: BADGES.FILE,
  COMPUTE_GATE: BADGES.USER,
};

const PACK_EVERY = 10;

// 步骤⑥ 审计链:四色哈希链 + 打包倒计时 + 立即打包 + Merkle 路径变红 + 争议双向面板
export default function Step6Audit({ response }) {
  const [logs, setLogs] = useState(null);
  const [packedThrough, setPackedThrough] = useState(0); // 已打包条目数(取 pack 响应 range,后端真值)
  const [packInfo, setPackInfo] = useState(null);
  const [redPath, setRedPath] = useState(false);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setLogs(await api.logs());
    } catch {
      setLogs(null);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const chain = logs?.chain || [];
  const merkle = logs?.merkle;
  const unpacked = Math.max(0, chain.length - packedThrough);
  const countdown = Math.max(0, PACK_EVERY - unpacked);

  const packNow = async () => {
    setBusy(true);
    try {
      const r = await api.logsPack();
      setPackInfo(r);
      if (Array.isArray(r?.range)) setPackedThrough(r.range[1] + 1);
      await refresh();
    } catch (e) {
      setPackInfo({ error: String(e?.message || e) });
    } finally {
      setBusy(false);
    }
  };

  // 模拟篡改(沙箱):后端真实验证失败(链断)后,Merkle 路径逐节点变红(动画由真实结果驱动)
  const simulateTamper = async () => {
    setBusy(true);
    try {
      const r = await api.attackInject("tamper_log");
      if (r && r.ok === false) setRedPath(true);
    } catch {
      /* 忽略 */
    } finally {
      setBusy(false);
    }
  };

  const clearTamper = async () => {
    setBusy(true);
    try {
      await api.attackReset();
      setRedPath(false);
      await refresh();
    } catch {
      /* 忽略 */
    } finally {
      setBusy(false);
    }
  };

  // 争议双向面板数据(全部后端值,前端只做字符串比对,不自算哈希)
  const filePayloads = response?.outbound?.file_payloads || [];
  const userDispute = filePayloads.map((f) => ({
    name: f.filename_token,
    uploadHash: f.file_content_hash || f.file_hash,
    outboundHash: f.file_hash,
    match: (f.file_content_hash || f.file_hash) === f.file_hash,
  }));
  const integrityLayer = (response?.verification || []).find((v) => v.layer === "响应完整性");

  return (
    <div className="space-y-4">
      {/* 哈希链 + 打包触发器 */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">审计哈希链(GET /api/logs)</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.AUDIT}
          </span>
          <span className={`px-2 py-0.5 rounded-full border text-[11px] font-medium ${
            logs?.chain_valid
              ? "border-ok/25 bg-ok-soft text-ok"
              : "border-bad/25 bg-bad-soft text-bad"
          }`}>
            主链 verify() = {logs ? String(logs.chain_valid) : "(…)"}
          </span>
          {/* 打包触发器徽章:倒计时 = PACK_EVERY - 未打包条目数 */}
          <span className="px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[11px] font-medium">
            ⏳ 距自动打包:{countdown} 条(未打包 {unpacked})
          </span>
          <button
            onClick={packNow}
            disabled={busy}
            className="ml-auto px-3 py-1.5 rounded-lg bg-vault-500 text-white text-[12px] font-semibold hover:bg-vault-600 disabled:opacity-50"
          >
            立即打包(Merkle)
          </button>
          <button
            onClick={refresh}
            disabled={busy}
            className="px-3 py-1.5 rounded-lg border border-line bg-paper text-[12px] text-ink-soft hover:border-vault-300"
          >
            刷新
          </button>
        </div>
        {packInfo && (
          <div className="px-4 pt-3 mono text-[10px] text-ink-faint break-all">
            pack → merkle_root = {packInfo.merkle_root || packInfo.error || "(…)"} · range = {JSON.stringify(packInfo.range ?? null)}
          </div>
        )}
        <div className="p-4 space-y-1.5 max-h-72 overflow-y-auto">
          {chain.length === 0 && <p className="text-[12px] text-ink-faint">(链为空 —— 发起查询后入链)</p>}
          {chain.map((e) => {
            const cls = ENTRY_COLORS[e.entry_type] || ENTRY_COLORS.QUERY;
            return (
              <div key={e.index} className={`rounded-lg border px-3 py-2 ${cls} transition-colors duration-500 ${redPath && e.entry_type !== "QUERY" ? "opacity-70" : ""}`}>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="mono text-[10px] opacity-70">#{e.index}</span>
                  <span className="text-[11px] font-semibold">{e.entry_type}</span>
                  <span className="px-1.5 py-0.5 rounded-full border border-current/20 text-[10px] opacity-80">
                    {ENTRY_BADGE[e.entry_type] || BADGES.AUDIT}
                  </span>
                  <span className="mono text-[10px] opacity-70 ml-auto">{e.timestamp}</span>
                </div>
                <div className="mt-1 mono text-[10px] break-all opacity-80">
                  p = {String(e.payload_digest).slice(0, 64)} · h = {String(e.hash).slice(0, 32)}… · prev = {String(e.prev_hash).slice(0, 16)}…
                </div>
              </div>
            );
          })}
        </div>
        <div className="px-4 pb-4 mono text-[10px] text-ink-faint break-all">
          chain_root = {logs?.chain_root || "(…)"}
        </div>
      </div>

      {/* Merkle 树 + 篡改路径变红(动画由后端验证结果驱动,不自算节点哈希) */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
          <span className="text-[13px] font-semibold text-ink">Merkle 树(打包完整性)</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.BIND}
          </span>
          <span className="text-[11px] text-ink-faint">节点哈希全部取自后端 merkle.levels(前端零自算)</span>
          <button
            onClick={simulateTamper}
            disabled={busy}
            className="ml-auto px-3 py-1.5 rounded-lg border border-bad/40 bg-bad-soft text-bad text-[12px] font-semibold hover:bg-bad hover:text-white disabled:opacity-50"
          >
            模拟篡改(沙箱)
          </button>
          <button
            onClick={clearTamper}
            disabled={busy}
            className="px-3 py-1.5 rounded-lg border border-ok/40 bg-ok-soft text-ok text-[12px] font-semibold hover:bg-ok hover:text-white disabled:opacity-50"
          >
            清除红闪
          </button>
        </div>
        <div className="p-4 space-y-2">
          {merkle ? (
            <>
              {[...merkle.levels].reverse().map((level, li) => (
                <div key={li} className="flex items-center gap-1 flex-wrap">
                  <span className="text-[10px] text-ink-faint w-14 shrink-0">
                    {li === 0 ? "root" : `L${merkle.levels.length - 1 - li}`}
                  </span>
                  {level.map((node, ni) => (
                    <span
                      key={ni}
                      title={node}
                      className={`px-1.5 py-1 rounded border mono text-[9px] transition-colors duration-500 ${
                        redPath
                          ? "border-bad bg-bad text-white alert-pulse"
                          : li === 0
                            ? "border-vault-300 bg-vault-50 text-vault-700"
                            : "border-line bg-paper text-ink-faint"
                      }`}
                      style={redPath ? { transitionDelay: `${(li * level.length + ni) * 40}ms` } : undefined}
                    >
                      {String(node).slice(0, 10)}…
                    </span>
                  ))}
                </div>
              ))}
              <div className="mono text-[10px] text-ink-faint break-all pt-1">
                merkle.root = {merkle.root} · leaves = {merkle.leaf_count}
              </div>
              <div className={`text-[11px] ${redPath ? "text-bad font-semibold" : "text-ink-soft"}`}>
                {redPath
                  ? "篡改演示:链断红闪,路径逐节点变红(沙箱验证结果驱动;主链 verify() 仍为真,见上)"
                  : "点击「模拟篡改」观察失败定位动画(沙箱隔离,不影响主链)"}
              </div>
            </>
          ) : (
            <p className="text-[12px] text-ink-faint">(加载中 / 无数据)</p>
          )}
        </div>
      </div>

      {/* 争议解决面板(双向验真) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="rounded-xl border border-line bg-surface">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
            <span className="text-[13px] font-semibold text-ink">争议面板 · 用户侧</span>
            <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
              {BADGES.FILE}
            </span>
            <span className="text-[11px] text-ink-faint">file_hash 重算比对(指控"内容被偷换")</span>
          </div>
          <div className="p-4 space-y-2">
            {userDispute.length === 0 && (
              <p className="text-[12px] text-ink-faint">本次请求无文件载荷。上传文件后发送,可现场比对 file_hash。</p>
            )}
            {userDispute.map((d, i) => (
              <div key={i} className="rounded-lg border border-line bg-paper px-3 py-2 mono text-[10px] space-y-1">
                <div className="text-[11px] font-semibold text-ink">{d.name}</div>
                <div className="break-all text-ink-faint">本地重算 file_hash = {d.uploadHash}</div>
                <div className="break-all text-ink-faint">链上/出站 file_hash = {d.outboundHash}</div>
                <div className={d.match ? "text-ok font-semibold" : "text-bad font-semibold"}>
                  {d.match ? "比对一致 → 指控不成立" : "比对失配 → 内容被偷换"}
                </div>
              </div>
            ))}
            <div className="text-[11px] text-ink-soft">
              链上 FILE_COMMIT 条目留有承诺;哈希比对只做字符串对照,现场可复算 SHA-256。
            </div>
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70 flex-wrap">
            <span className="text-[13px] font-semibold text-ink">争议面板 · 服务商侧</span>
            <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
              {BADGES.SIGN}
            </span>
            <span className="text-[11px] text-ink-faint">response_hash 验签(指控"服务商未发出该输出")</span>
          </div>
          <div className="p-4 space-y-2">
            <div className="rounded-lg border border-line bg-paper px-3 py-2 mono text-[10px] space-y-1">
              <div className="break-all text-ink-faint">response_hash = {response?.response_hash || "(…)"}</div>
              <div className="break-all text-ink-faint">
                签名 = {String(response?.signature || "(…)").slice(0, 64)}…
              </div>
              <div className={integrityLayer?.ok ? "text-ok font-semibold" : "text-bad font-semibold"}>
                {response
                  ? integrityLayer?.ok
                    ? "Ed25519 验签通过 → 签名覆盖 input_hash,与链上一致,抵赖不成立"
                    : `验签结果:${integrityLayer?.detail || "(…)"
                      }`
                  : "等待步骤① 发送…"}
              </div>
            </div>
            <div className="text-[11px] text-ink-soft">
              签名覆盖 output ‖ input_hash ‖ model_cert ‖ nonce ‖ timestamp,服务商无法选择性否认。
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
