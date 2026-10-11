"""
对抗负例生成器(Golden Set 子集:150 单元 / ≥400 非敏感分句)—— FPR 主战场

每个负例 gold=[](整单元非敏感)。类别覆盖 spec §6.1 / Task 18 简报:
  - 订单号 16 位但 Luhn 挂(似卡号)         ← 有意触发 CARD 误报,衡量 FPR
  - 版本号 1.2.3.4(似 IP)                  ← 有意触发 IP 误报
  - 版本号 v1.2.3(3 段,不构成 IPv4)       ← 安全负例
  - 日期 20251015 / 2025-10-15 / 2025年10月15日(似手机号/证件号)
  - π 取 20 位小数(长数字串,似证件号/卡号)
  - 3-4-5 短横线编号(似结构化号码)
  - 长横线号 2025-10-15-001(似流水号)
  - 其他安全负例:短数字、时刻、分数、1e3 计数

生成确定性:random.Random(20261011)。分句切分与 detection_golden.py 同口径
([。;;!?!?\\n])。构造约束:任何负例分句内不得出现 13-19 位连续数字、
IPv4、18 位证件结构等触发形态(有意触发类除外)。
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.tokens import luhn_digit  # noqa: E402

SEED = 20261011

# 安全填充分句(不含任何词典词/正则触发形态)
_FILLERS = [
    "系统升级已完成", "会议记录整理完毕", "材料已归档", "设备运行平稳",
    "排班表已更新", "样品已入库", "打印机墨盒已更换", "请稍后重试",
    "流程已经走完", "附件已经发出", "值班安排见通知", "机房巡检正常",
    "窗帘已经更换", "绿植养护完成", "门禁卡已登记", "车辆已入场",
    "耗材已补充", "投影仪已归还", "雨天路滑注意安全", "培训材料已下发",
]


def _order16_luhn_fail(rng: random.Random) -> str:
    """16 位订单号:Luhn 必挂(第 16 位取错,似卡号但校验不过)。"""
    head = "".join(rng.choice("0123456789") for _ in range(15))
    good = luhn_digit(head)
    bad = str((int(good) + 1 + rng.randrange(9)) % 10)   # ≠ good → Luhn 挂
    if bad == good:
        bad = str((int(good) + 1) % 10)
    return head + bad


def _version4(rng: random.Random) -> str:
    return f"{rng.randrange(1, 3)}.{rng.randrange(0, 9)}.{rng.randrange(0, 9)}.{rng.randrange(0, 9)}"


def _pi20(rng: random.Random) -> str:
    # 3. + 20 位小数:20 位连续数字不满足 CARD 正则(13-19 位)边界
    return "3.14159265358979323846"


def _date_forms(rng: random.Random) -> str:
    forms = [
        "20251015", "2025-10-15", "2025年10月15日", "2025/10/15",
        "20251130", "2025-12-01", "20260101", "2026-02-28",
    ]
    return rng.choice(forms)


def _short_dash(rng: random.Random) -> str:
    forms = ["3-4-5", "7-2-9", "12-3-8", "5-11-2", "2-2-2", "9-1-6"]
    return rng.choice(forms)


def _long_dash_id(rng: random.Random) -> str:
    forms = [
        "2025-10-15-001", "2026-03-08-042", "2025-12-31-100",
        "2026-01-01-007", "2025-11-11-055",
    ]
    return rng.choice(forms)


def _misc(rng: random.Random) -> str:
    forms = [
        f"第{rng.randrange(1, 9)}-{rng.randrange(1, 9)}-{rng.randrange(1, 9)}节",
        f"{rng.randrange(8, 18):02d}:{rng.randrange(0, 60):02d}:00",
        f"{rng.randrange(1, 9)}/{rng.randrange(2, 9)}",
        f"1e{rng.randrange(1, 4)}",
        f"{rng.randrange(1000, 9999)}",
        f"{rng.randrange(100000, 999999)}",
        f"v{rng.randrange(1, 5)}.{rng.randrange(0, 9)}.{rng.randrange(0, 9)}",
    ]
    return rng.choice(forms)


# (生成函数, 句式, 是否有意触发误报)
_CATS = [
    ("order16_luhnfail", lambda r: _order16_luhn_fail(r), "订单号是{v}。", True, 10),
    ("version_4octet", _version4, "版本号是{v}。", True, 8),
    ("version_3octet", _misc, "内核版本{v}。", False, 12),
    ("date_compact", _date_forms, "发布日期{v}。", False, 25),
    ("pi_20dec", _pi20, "圆周率取20位是{v}。", False, 20),
    ("short_dash", _short_dash, "排线编号{v}。", False, 25),
    ("long_dash_id", _long_dash_id, "归档编号{v}。", False, 25),
    ("misc_safe", _misc, "参数取值{v}。", False, 25),
]


def build_adversarial() -> list[dict]:
    """150 对抗负例单元:每单元 3 分句(触发/载荷分句 + 2 填充分句),gold=[]。"""
    rng = random.Random(SEED)
    out: list[dict] = []
    for name, gen, tmpl, _triggers, n in _CATS:
        for _ in range(n):
            payload = tmpl.format(v=gen(rng))
            f1, f2 = rng.sample(_FILLERS, 2)
            text = f"{f1}。{payload}{f2}。"
            out.append({
                "text": text,
                "gold": [],
                "modality": "plain",
                "subset": "adversarial",
            })
    assert len(out) == 150, len(out)
    return out


if __name__ == "__main__":     # 自检:150 单元 / 分句 ≥400
    recs = build_adversarial()
    import re
    split = re.compile(r"[。;;！？!?\n]")
    n_sent = sum(len([s for s in split.split(r["text"]) if s.strip()]) for r in recs)
    print(f"adversarial units={len(recs)} sentences={n_sent}")
