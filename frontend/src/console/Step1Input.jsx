import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { BADGES } from "./badges.js";

const TIER_TEXT = {
  readable: { label: "📄 可读通道", cls: "bg-vault-50 text-vault-700 border-vault-200" },
  evidence: { label: "🔒 存证通道(模型不可读)", cls: "bg-crypto-violetSoft text-crypto-violet border-crypto-violet/25" },
};

const ACTIONS = [
  { key: "force_allow", label: "放行" },
  { key: "manual_replace", label: "手动替换" },
  { key: "force_redact", label: "强制脱敏" },
];

// 步骤① 输入:对话/文件 Tab + 实时高亮 + 待确认三选一 + user_ack + override 芯片条
export default function Step1Input({
  text, onTextChange, scenario, onScenarioChange,
  detect, onDetect, fileItems, onFilesChange,
  onSend, sending,
}) {
  const [tab, setTab] = useState("text");
  const [decisions, setDecisions] = useState({}); // entity idx -> {action, replacement}
  const [userAck, setUserAck] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef(null);
  const abortRef = useRef(0);

  // debounce 300ms → POST /api/detect(预览高亮,真发走 query2)
  useEffect(() => {
    if (!text) { onDetect(null); return; }
    const seq = ++abortRef.current;
    const t = setTimeout(async () => {
      try {
        const r = await api.detect(text, scenario);
        if (seq === abortRef.current) onDetect(r);
      } catch { /* 预览失败不阻塞输入 */ }
    }, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, scenario]);

  const entities = detect?.entities || [];
  const pending = entities
    .map((e, i) => ({ ...e, idx: i }))
    .filter((e) => Number(e.confidence) < 0.6);
  const unresolved = pending.filter((e) => !decisions[e.idx]);
  const needAck = pending.length > 0;
  const canSend = !!text && !sending && unresolved.length === 0 && (!needAck || userAck);

  // override 芯片条数据(数组整体哈希 → input_hash)
  const overrideChips = pending
    .filter((e) => decisions[e.idx])
    .map((e) => ({
      idx: e.idx,
      text: `${e.zh} · ${ACTIONS.find((a) => a.key === decisions[e.idx].action)?.label || decisions[e.idx].action}`,
      action: decisions[e.idx].action,
      replacement: decisions[e.idx].replacement,
    }));

  const buildOverrides = () =>
    pending
      .filter((e) => decisions[e.idx])
      .map((e) => ({
        event_id: `ov_${e.idx}_${Date.now()}`,
        entity_span: [e.start, e.end],
        entity_type: e.type,
        original_token: e.placeholder,
        action: decisions[e.idx].action,
        replacement: decisions[e.idx].replacement || null,
        user_ack: true,
        ts: new Date().toISOString(),
      }));

  // 高亮块:按实体区间切原始文本(徽章 ⚠️ NLP·非密码学)
  const renderHighlight = () => {
    if (!text) return null;
    const sorted = [...entities].sort((a, b) => a.start - b.start);
    const out = [];
    let pos = 0;
    sorted.forEach((e, i) => {
      if (e.start > pos) out.push(<span key={`t${i}`}>{text.slice(pos, e.start)}</span>);
      out.push(
        <mark
          key={`e${i}`}
          title={`${e.zh}(${e.type})·置信度 ${e.confidence}·方法 ${e.method}`}
          className={`rounded px-0.5 ${
            Number(e.confidence) < 0.6
              ? "bg-warn-soft text-warn ring-1 ring-warn/40"
              : "bg-vault-100 text-vault-800 ring-1 ring-vault-200"
          }`}
        >
          {text.slice(e.start, e.end)}
          <span className="mono text-[9px] ml-1 opacity-70">{e.type}</span>
        </mark>
      );
      pos = e.end;
    });
    if (pos < text.length) out.push(<span key="tail">{text.slice(pos)}</span>);
    return out;
  };

  const handleFiles = async (fl) => {
    const items = [...fileItems];
    for (const f of fl) {
      try {
        const info = await api.uploadFile(f);
        items.push({ file: f, info });
      } catch (e) {
        items.push({ file: f, info: { error: String(e.message || e) } });
      }
    }
    onFilesChange(items);
  };

  return (
    <div className="space-y-4">
      {/* Tab 切换 */}
      <div className="flex items-center gap-2">
        {["text", "file"].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-lg text-[13px] font-medium border ${
              tab === t
                ? "bg-vault-500 text-white border-vault-500"
                : "bg-surface text-ink-soft border-line hover:border-vault-300"
            }`}
          >
            {t === "text" ? "💬 对话输入" : "📁 文件输入"}
          </button>
        ))}
        <select
          value={scenario}
          onChange={(e) => onScenarioChange(e.target.value)}
          className="ml-auto px-3 py-1.5 rounded-lg border border-line bg-surface text-[12px] text-ink"
        >
          <option value="medical">医疗场景</option>
          <option value="financial">金融场景</option>
        </select>
      </div>

      {tab === "text" && (
        <>
          {/* 实时高亮(检测是正则,产物从这一步起进入密码学管道,请看②) */}
          <div className="rounded-xl border border-line bg-surface">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
              <span className="text-[13px] font-semibold text-ink">实时高亮预览</span>
              <span className="px-2 py-0.5 rounded-full border border-warn/25 bg-warn-soft text-warn text-[11px] font-medium">
                {BADGES.NLP}
              </span>
              <span className="text-[11px] text-ink-faint">
                检测层是正则/词典 —— 产物从这一步起进入密码学管道,请看②
              </span>
            </div>
            <textarea
              value={text}
              onChange={(e) => onTextChange(e.target.value)}
              rows={5}
              placeholder="输入含敏感数据的对话文本…"
              className="w-full px-4 py-3 text-[13px] text-ink bg-transparent outline-none resize-y border-b border-line/70"
            />
            <div className="px-4 py-3 text-[13px] leading-7 text-ink">{renderHighlight() || <span className="text-ink-faint">(空)</span>}</div>
            {detect && (
              <div className="px-4 pb-3 text-[11px] text-ink-faint mono">
                redacted = {detect.redacted || "(空)"} · 实体 {entities.length} 个
              </div>
            )}
          </div>
        </>
      )}

      {tab === "file" && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            handleFiles([...e.dataTransfer.files]);
          }}
          className={`rounded-xl border-2 border-dashed p-6 text-center bg-surface ${dragOver ? "border-vault-400 bg-vault-50" : "border-line"}`}
        >
          <p className="text-[13px] text-ink-soft">拖放文件到此处,或</p>
          <button
            onClick={() => fileRef.current?.click()}
            className="mt-2 px-4 py-2 rounded-lg bg-vault-500 text-white text-[13px] font-medium"
          >
            选择文件
          </button>
          <input
            ref={fileRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => { handleFiles([...e.target.files]); e.target.value = ""; }}
          />
          <div className="mt-4 space-y-2 text-left">
            {fileItems.length === 0 && (
              <p className="text-[11px] text-ink-faint">
                上传即路由:可读通道正文脱敏出站 / 存证通道只出承诺(默认拒绝)
              </p>
            )}
            {fileItems.map((it, i) => {
              const tier = TIER_TEXT[it.info?.content_tier] || { label: "路由失败", cls: "bg-bad-soft text-bad border-bad/25" };
              return (
                <div key={i} className="rounded-lg border border-line bg-paper px-3 py-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[12px] font-medium text-ink">{it.file.name}</span>
                    <span className={`px-2 py-0.5 rounded-full border text-[11px] font-medium ${tier.cls}`}>{tier.label}</span>
                    <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
                      {BADGES.PRF} 文件名令牌
                    </span>
                    <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
                      {BADGES.FILE}
                    </span>
                  </div>
                  <div className="mt-1 mono text-[10px] text-ink-faint break-all">
                    filename_token = {it.info?.filename_token || it.info?.error || "(…)"}
                  </div>
                  {it.info?.file_hash && (
                    <div className="mono text-[10px] text-ink-faint break-all">file_hash = {it.info.file_hash}</div>
                  )}
                  {it.info?.content_tier === "readable" && it.info?.text_excerpt && (
                    <div className="mt-1 text-[11px] text-ink-soft">
                      正文摘录({it.info.text_chars} 字符):{it.info.text_excerpt}
                    </div>
                  )}
                  {it.info?.content_tier === "evidence" && (
                    <div className="mt-1 text-[11px] text-crypto-violet">
                      存证通道:正文不出网,仅 vault_ct 承诺出站(模型不可读)
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 待确认清单:三选一 + user_ack 强制 */}
      <div className="rounded-xl border border-line bg-surface">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line/70">
          <span className="text-[13px] font-semibold text-ink">待确认清单(低置信度实体)</span>
          <span className="px-2 py-0.5 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.USER}
          </span>
          <span className="text-[11px] text-ink-faint">决策入 override_events → 数组整体哈希 → input_hash → 链上 USER_OVERRIDE</span>
        </div>
        <div className="p-4 space-y-3">
          {pending.length === 0 && (
            <p className="text-[12px] text-ink-faint">当前无低置信度实体(&lt;0.6)。输入更口语化文本可触发待确认流程。</p>
          )}
          {pending.map((e) => {
            const d = decisions[e.idx] || {};
            return (
              <div key={e.idx} className="rounded-lg border border-line bg-paper px-3 py-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[12px] font-semibold text-ink">{e.zh}({e.type})</span>
                  <span className="mono text-[11px] text-ink-soft">“{e.value}”</span>
                  <span className="text-[10px] text-warn font-medium">置信度 {e.confidence}</span>
                  <span className="text-[10px] text-ink-faint">方法 {e.method}</span>
                </div>
                <div className="mt-2 flex items-center gap-2 flex-wrap">
                  {ACTIONS.map((a) => (
                    <button
                      key={a.key}
                      onClick={() => setDecisions((s) => ({ ...s, [e.idx]: { action: a.key, replacement: s[e.idx]?.replacement } }))}
                      className={`px-3 py-1 rounded-lg text-[12px] border ${
                        d.action === a.key
                          ? "bg-vault-500 text-white border-vault-500"
                          : "bg-surface text-ink-soft border-line hover:border-vault-300"
                      }`}
                    >
                      {a.label}
                    </button>
                  ))}
                  {d.action === "manual_replace" && (
                    <input
                      value={d.replacement || ""}
                      onChange={(ev) => setDecisions((s) => ({ ...s, [e.idx]: { action: "manual_replace", replacement: ev.target.value } }))}
                      placeholder="替换值"
                      className="px-2 py-1 rounded-lg border border-line bg-surface text-[12px] mono w-40"
                    />
                  )}
                </div>
              </div>
            );
          })}
          {needAck && (
            <label className="flex items-center gap-2 text-[12px] text-ink">
              <input
                type="checkbox"
                checked={userAck}
                onChange={(ev) => setUserAck(ev.target.checked)}
                className="h-4 w-4 accent-vault-500"
              />
              user_ack:我确认上述人工决策并同意其经哈希绑定进 input_hash(不可抵赖)
            </label>
          )}
        </div>
      </div>

      {/* override 芯片条 */}
      <div className="rounded-xl border border-line bg-surface px-4 py-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-semibold text-ink-soft">override 事件</span>
          {overrideChips.length === 0 && <span className="text-[11px] text-ink-faint">(暂无)</span>}
          {overrideChips.map((c) => (
            <span
              key={c.idx}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium"
            >
              {c.text}
              {c.replacement && <span className="mono text-[10px]">→ {c.replacement}</span>}
            </span>
          ))}
          <span className="ml-auto inline-flex items-center gap-1 px-2.5 py-1 rounded-full border border-vault-200 bg-vault-50 text-vault-700 text-[11px] font-medium">
            {BADGES.BIND} 数组整体哈希 → input_hash
          </span>
        </div>
      </div>

      {/* 发送 */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => onSend(buildOverrides())}
          disabled={!canSend}
          className="px-6 py-2.5 rounded-lg bg-vault-500 text-white text-[14px] font-semibold shadow-[0_2px_8px_-2px_rgba(67,97,238,0.5)] hover:bg-vault-600 disabled:opacity-50 disabled:pointer-events-none"
        >
          {sending ? "发送中…" : "发送 → CG/2.0 出站"}
        </button>
        <span className="text-[11px] text-ink-faint">
          发送即 POST /api/proxy/query2(schema_version=CG/2.0),响应驱动步骤②–⑥
        </span>
      </div>
    </div>
  );
}
