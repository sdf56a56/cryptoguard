"""
Golden Set 400 检测指标 —— P / R / FPR + Wilson 95% CI(spec §6.1)

口径(分句 = 分句单元):
  Precision = TP/(TP+FP)  > 95%   (span 级精确匹配:类型 + [start,end) 全等)
  Recall    = TP/(TP+FN)  > 90%
  FPR       = FP/(FP+TN)  <  5%   (分母 = 对抗负例的非敏感分句单元,≥400)

输出 per-type 与 overall 混淆矩阵 + Wilson 95% CI(点估计 + CI,不给裸数);
退出码 0 = 三项全达标且 FPR CI 半宽 ≤±3%,1 = 不达标(指标如实报告,不造假)。

诚实边界:指标是该测试集上的实测值,不承诺对抗性变形输入(同音字、零宽字符)。
文件链路抽取损耗归因抽取器,不算检测器(单列,本集为纯文本单元 = N/A)。

运行(R12:项目根 tests/ 独立脚本,自带 backend 路径注入):
    py tests/detection_golden.py
"""
from __future__ import annotations

import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.detection import detect_sensitive  # noqa: E402
from golden_gen import build_golden_set  # noqa: E402

P_MIN, R_MIN, FPR_MAX, FPR_HALFWIDTH_MAX = 0.95, 0.90, 0.05, 0.03

_SPLIT = re.compile(r"[。;;！？!?\n]")


def wilson_ci(phat: float, n: float, z: float = 1.96):
    """Wilson score interval(95%)。"""
    d = 1 + z * z / n
    c = phat + z * z / (2 * n)
    h = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def _sentence_spans(text: str) -> list[tuple[int, int]]:
    """分句单元区间(与 FPR 分母同口径)。"""
    spans = []
    start = 0
    for m in _SPLIT.finditer(text):
        if text[start:m.start()].strip():
            spans.append((start, m.start()))
        start = m.end()
    if text[start:].strip():
        spans.append((start, len(text)))
    return spans


def evaluate(records: list[dict]) -> dict:
    tp = fp = fn = 0
    per_type = defaultdict(lambda: Counter())
    fp_rows: list[str] = []
    fn_rows: list[str] = []

    # FPR:对抗负例分句单元
    fpr_fp = fpr_tn = 0

    for rec in records:
        det = detect_sensitive(rec["text"])
        gold = {(g["type"], g["span"][0], g["span"][1]) for g in rec["gold"]}
        pred = {(e.type, e.start, e.end) for e in det.entities}

        for g in sorted(gold & pred):
            tp += 1
            per_type[g[0]]["TP"] += 1
        for g in sorted(gold - pred):
            fn += 1
            per_type[g[0]]["FN"] += 1
            fn_rows.append(f"[{rec['subset']}] gold={g} text={rec['text'][:40]!r}")
        for p in sorted(pred - gold):
            fp += 1
            per_type[p[0]]["FP"] += 1
            fp_rows.append(f"[{rec['subset']}] pred={p} text={rec['text'][:40]!r}")

        if rec["subset"] == "adversarial":
            sents = _sentence_spans(rec["text"])
            flagged = set()
            for e in det.entities:
                for i, (s0, s1) in enumerate(sents):
                    if s0 <= e.start < s1:
                        flagged.add(i)
            fpr_fp += len(flagged)
            fpr_tn += len(sents) - len(flagged)

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "per_type": per_type,
        "fp_rows": fp_rows, "fn_rows": fn_rows,
        "fpr_fp": fpr_fp, "fpr_tn": fpr_tn,
    }


def main() -> int:
    records = build_golden_set()
    r = evaluate(records)
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    fpr_fp, fpr_tn = r["fpr_fp"], r["fpr_tn"]
    n_neg = fpr_fp + fpr_tn

    p = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fpr_fp / n_neg if n_neg else 0.0
    p_ci = wilson_ci(p, tp + fp)
    r_ci = wilson_ci(recall, tp + fn)
    fpr_ci = wilson_ci(fpr, n_neg)
    fpr_hw = (fpr_ci[1] - fpr_ci[0]) / 2

    subsets = Counter(rec["subset"] for rec in records)
    print("=== Golden Set 400 检测指标(实测,span 级精确匹配)===")
    print(f"子集构成: 模板 {subsets['template']} / 复合 {subsets['composite']} "
          f"/ 对抗 {subsets['adversarial']} / 跨模态 {subsets['crossmodal']}")
    print(f"对抗负例非敏感分句单元: {n_neg}(要求 ≥400)")
    print()
    print("per-type:")
    print(f"{'type':<8}{'TP':>5}{'FP':>5}{'FN':>5}{'P':>8}{'R':>8}")
    for t in sorted(r["per_type"]):
        c = r["per_type"][t]
        tp_t, fp_t, fn_t = c["TP"], c["FP"], c["FN"]
        pt = tp_t / (tp_t + fp_t) if tp_t + fp_t else 1.0
        rt = tp_t / (tp_t + fn_t) if tp_t + fn_t else 1.0
        print(f"{t:<8}{tp_t:>5}{fp_t:>5}{fn_t:>5}{pt:>8.3f}{rt:>8.3f}")
    print()
    print(f"Overall: TP={tp} FP={fp} FN={fn}  "
          f"FPR 分句: FP={fpr_fp} TN={fpr_tn}")
    print(f"Precision = {p:.4f}  Wilson95% [{p_ci[0]:.4f}, {p_ci[1]:.4f}]")
    print(f"Recall    = {recall:.4f}  Wilson95% [{r_ci[0]:.4f}, {r_ci[1]:.4f}]")
    print(f"FPR       = {fpr:.4f}  Wilson95% [{fpr_ci[0]:.4f}, {fpr_ci[1]:.4f}]"
          f"  半宽 ±{fpr_hw:.4f}")
    print("抽取损耗: N/A(纯文本单元;文件抽取损耗归因抽取器,单列,不计检测器)")
    print()

    if r["fp_rows"]:
        print(f"FP 样例(前 10,共 {len(r['fp_rows'])}):")
        for row in r["fp_rows"][:10]:
            print("  " + row)
    if r["fn_rows"]:
        print(f"FN 样例(前 10,共 {len(r['fn_rows'])}):")
        for row in r["fn_rows"][:10]:
            print("  " + row)
    print()

    checks = [
        ("P > 95%", p > P_MIN),
        ("R > 90%", recall > R_MIN),
        ("FPR < 5%", fpr < FPR_MAX),
        ("FPR CI 半宽 ≤ ±3%", fpr_hw <= FPR_HALFWIDTH_MAX),
        ("分句 ≥ 400", n_neg >= 400),
    ]
    for name, ok in checks:
        print(f"达标判定: {name:<16} {'PASS' if ok else 'FAIL'}")
    passed = all(ok for _, ok in checks)
    print(f"RESULT: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
