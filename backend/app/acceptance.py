"""
验收模块 —— /demo 验收抽屉数据源(Task 12)

四路验收数据(spec §6.2/§6.3):
  - run_golden():Golden Set 400 实测 P/R/FPR + Wilson 95% CI + per-type
    (口径与 tests/detection_golden.py 逐字一致,零分母兜 0.0);
  - scan_plaintext_leaks():数据目录 *.ndjson 逐行 JSON、递归键名查
    user_view / reasoning_content / mapping / restore_map(SEC-STORE-1 演示按钮
    真报;精确键名口径,reasoning_ct / *_ct 均合法);
  - replay_report():对数据目录重建 ChatService 只读回放(SEC-REPLAY-1),
    成功给链/会话/消息计数,失败给错误类别,不改活服务;
  - degrade_demo():三类故障经真实 LLMGateway 注入,捕获 spec §5 行为三元组
    (SEC-DEGRADE-1)。

安全目标:
  - 扫描器只读:绝不写数据目录;泄漏判定仅看键名,不看值(值可能本就合法)。
  - 回放报告只验不改:build_chat_service 对活数据目录仅读取/验封缄,
    与在跑的 ChatService 互不干扰(单写者模型下无追加)。

明确不承诺:
  - 不承诺扫出"键名合法但值为明文"的泄漏(如 llm_view 被塞明文):
    键名口径之外的语义泄漏不在此列;
  - degrade_demo 的 stub 故障不代表真实 MiMo 行为面,仅复现 §5 表三分类。
"""
from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .bootstrap import build_chat_service
from .keys import VaultKeyError
from .llm import LLMFailure, LLMGateway, MockChat, OnToken, ReplyStream
from .store import StoreIntegrityError

#: 明文泄漏嫌疑键(精确键名;reasoning_ct / mapping_delta_ct 等 *_ct 封缄形态合法)
LEAK_KEYS = ("user_view", "reasoning_content", "mapping", "restore_map")

#: degrade_demo 允许的故障类别(spec §5 三分类)
DEMO_KINDS = ("network", "protocol", "stream")


# --------------------------------------------------------------------------- #
# Golden Set 400 指标(P/R/FPR + Wilson 95% CI)
# --------------------------------------------------------------------------- #
def run_golden() -> dict:
    """跑 Golden Set 400,返回整体/分型混淆矩阵与 Wilson 95% CI。

    复用 tests/detection_golden.py 的 evaluate/wilson_ci 与
    tests/golden_gen.py 的 build_golden_set(路径在调用时注入 sys.path,
    后端进程内直接可跑);零分母指标与 CI 一律兜 0.0,不抛除零。
    """
    root = Path(__file__).resolve().parent.parent.parent
    for p in (str(root / "backend"), str(root / "tests")):
        if p not in sys.path:
            sys.path.insert(0, p)
    # 函数内导入:依赖上方 sys.path 注入,顶部不可导
    from detection_golden import evaluate, wilson_ci
    from golden_gen import build_golden_set

    r = evaluate(build_golden_set())
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    n_neg = r["fpr_fp"] + r["fpr_tn"]

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = r["fpr_fp"] / n_neg if n_neg else 0.0

    def _ci(phat: float, n: int) -> list[float]:
        return list(wilson_ci(phat, n)) if n else [0.0, 0.0]

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "p": prec, "r": rec, "fpr": fpr,
        "p_ci": _ci(prec, tp + fp),
        "r_ci": _ci(rec, tp + fn),
        "fpr_ci": _ci(fpr, n_neg),
        "per_type": {
            t: {"TP": int(c["TP"]), "FP": int(c["FP"]), "FN": int(c["FN"])}
            for t, c in sorted(r["per_type"].items())
        },
        "n_neg_units": n_neg,
    }


# --------------------------------------------------------------------------- #
# 明文泄漏扫描(SEC-STORE-1 演示按钮)
# --------------------------------------------------------------------------- #
def scan_plaintext_leaks(data_dir: Path) -> dict:
    """扫 data_dir 下全部 *.ndjson:逐行 JSON、递归键名查 LEAK_KEYS。

    返回 {"checked_files", "checked_lines", "leaks": [{"file","line","path"}]};
    file 为相对 data_dir 的 posix 路径,path 为点/下标定位(如 a.b[0].user_view)。
    非 JSON 行计入 checked_lines 但不判泄漏(键名口径);leaks 空 = 干净。
    """
    checked_files = 0
    checked_lines = 0
    leaks: list[dict] = []
    for path in sorted(data_dir.rglob("*.ndjson")):
        checked_files += 1
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(data_dir).as_posix()
        for lineno, line in enumerate(lines, 1):
            checked_lines += 1
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            _walk_keys(obj, "", rel, lineno, leaks)
    return {"checked_files": checked_files,
            "checked_lines": checked_lines,
            "leaks": leaks}


def _walk_keys(node: object, prefix: str, rel: str, lineno: int,
               leaks: list[dict]) -> None:
    """递归遍历全部键/下标;键名命中 LEAK_KEYS 即记 (file, line, path)。"""
    if isinstance(node, dict):
        for key, val in node.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            if key in LEAK_KEYS:
                leaks.append({"file": rel, "line": lineno, "path": child})
            _walk_keys(val, child, rel, lineno, leaks)
    elif isinstance(node, list):
        for i, val in enumerate(node):
            _walk_keys(val, f"{prefix}[{i}]", rel, lineno, leaks)


# --------------------------------------------------------------------------- #
# 回放报告(SEC-REPLAY-1)
# --------------------------------------------------------------------------- #
def replay_report(data_dir: Path) -> dict:
    """对 data_dir 重建 ChatService 只读回放,返回计数或错误类别。

    成功 {"ok": True, "chain_entries", "sessions", "messages"};
    VaultKeyError / StoreIntegrityError → {"ok": False, "error", "kind"}
    (kind = 异常类名,不吞错不美化)。
    """
    try:
        service = build_chat_service(data_dir)
    except (VaultKeyError, StoreIntegrityError) as exc:
        return {"ok": False, "error": str(exc), "kind": type(exc).__name__}
    sessions = service.sessions.list_sessions()
    return {
        "ok": True,
        "chain_entries": len(service.chain.entries),
        "sessions": len(sessions),
        "messages": len(service.sessions.messages_log.read_all()),
    }


# --------------------------------------------------------------------------- #
# 三类故障注入(spec §5 表,SEC-DEGRADE-1)
# --------------------------------------------------------------------------- #
class _FaultMimo:
    """故障注入 stub Mimo:按 kind 抛 LLMFailure 或返回断流 ReplyStream。

    明确不承诺:仅复现 §5 三分类触发面,不代表真实 MiMo 行为。
    """

    def __init__(self, kind: str) -> None:
        self.kind = kind

    def chat(self, messages: Sequence[dict],
             on_token: OnToken | None = None) -> ReplyStream:
        if self.kind == "network":
            raise LLMFailure("network", "stub:连接失败")
        if self.kind == "protocol":
            raise LLMFailure("protocol", "stub:HTTP 400")
        return ReplyStream(output="partial", reasoning_content="",
                           incomplete=True, degraded=None, model="stub-mimo")


def degrade_demo(kind: str) -> dict:
    """三类故障注入经真实 LLMGateway(mock=真 MockChat),捕获行为三元组。

    行为对齐 spec §5 表:network → 切 Mock(yellow-degrade, degraded="mock");
    protocol → 直接报错不降级(red-error);stream → 保留已收内容不完整
    (yellow-incomplete, incomplete=True)。ui_class 由实测状态(报错/降级/断流)
    推得,不写死。
    """
    if kind not in DEMO_KINDS:
        raise ValueError(f"非法故障类别: {kind!r}，仅允许 {DEMO_KINDS}")
    reply: ReplyStream | None = None
    error: LLMFailure | None = None
    gateway = LLMGateway(mimo=_FaultMimo(kind), mock=MockChat())
    try:
        reply = gateway.chat([{"role": "user", "content": "验收演示"}])
    except LLMFailure as exc:
        error = exc

    degraded = reply.degraded if reply is not None else None
    incomplete = bool(reply.incomplete) if reply is not None else False
    if error is not None:
        ui_class = "red-error"             # protocol:直接报错,无回复体
    elif degraded == "mock":
        ui_class = "yellow-degrade"        # network:切 Mock 降级
    elif incomplete:
        ui_class = "yellow-incomplete"     # stream:保留已收内容 + 不完整徽章
    else:  # pragma: no cover — stub 三类之外不可达
        ui_class = "red-error"
    return {"kind": kind, "ui_class": ui_class,
            "degraded": degraded, "incomplete": incomplete}
