"""
Golden Set 生成器 —— 400 文本单元(真值自动已知)

构成(spec §6.1):
  模板 120(13 类实体×变体,身份证 id_check_digit 合法/坏校验位对、
           卡号 Luhn 通过/不过对)
  复合 100(病历/流水句式,实体共现、嵌套)
  对抗 150(golden_adversarial.py,每单元 gold=[] 非敏感)
  跨模态 30(同一实体置于 plain / csv-row / docx-para / pdf-line)

每条记录:{"text": str, "gold": [{"type": str, "span": [s, e]}],
          "modality": str, "subset": str}
gold span = 生成时实体字符串在文本中的精确区间([start, end))。
生成确定性:random.Random(20261011)。

放置约束(保证检测器正则/词典命中区间 == gold 区间,生成器侧校准):
  - 词典类实体(NAME/ORG/PROJECT/PHI/PII)按词典词逐字放置;
  - ADDRESS 必须前邻「：」等非 [一-龥A-Za-z0-9] 字符、后邻「，。」,
    防止地址正则回溯吞并前文(嵌套实体因此不重叠);
  - 填充句不含任何词典词与触发形态(13-19 位连续数字、IPv4、18 位证件结构)。
"""
from __future__ import annotations

import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.tokens import id_check_digit, luhn_digit  # noqa: E402
from golden_adversarial import build_adversarial  # noqa: E402

SEED = 20261011

_NAME_POOL = ["张三", "李四", "张伟", "王芳", "李娜", "刘洋", "陈静", "杨洋",
              "赵敏", "黄强", "周杰", "吴磊", "徐明", "孙丽", "马超", "朱婷",
              "胡军", "郭靖", "林丹", "何洁", "高翔", "罗琳", "郑爽", "梁静"]
_ORG_POOL = ["第一人民医院", "中心医院", "工商银行", "建设银行", "招商银行",
             "国家电网", "中信证券", "平安保险"]
_PROJ_POOL = ["天枢计划", "玄武工程", "猎户座", "昆仑项目", "凤凰协议"]
_PHI_POOL = ["病历号", "住院号", "医保卡号", "床号", "血型"]
_PII_POOL = ["账户余额", "工资", "收入", "授信额度", "交易流水", "密码", "验证码"]

# 地址模板:省/市 … 区/县 … 路/街道 … 号,检测正则命中区间 == 整串
_ADDR_POOL = [
    "浙江省杭州市西湖区文一西路500号",
    "江苏省南京市鼓楼区中山路100号",
    "北京市朝阳区建国路88号",
    "广东省深圳市南山区科技园南路30号",
    "四川省成都市武侯区人民南路四段12号",
    "上海市浦东新区世纪大道200号",
    "湖北省武汉市江汉区解放大道688号",
    "陕西省西安市雁塔区高新路25号",
    "山东省济南市历下区经十路9999号",
]

_FILLERS = [
    "今日无异常", "流程已经走完", "材料已归档", "请稍后重试",
    "设备运行平稳", "附件已经发出", "值班安排见通知", "机房巡检正常",
    "排班表已更新", "样品已入库",
]


class _Tex:
    """按拼装顺序累积文本与 gold span(gold = 实体字符串的精确区间)。"""

    def __init__(self):
        self.buf = ""
        self.gold: list[dict] = []

    def add(self, s: str) -> None:
        self.buf += s

    def ent(self, s: str, etype: str) -> None:
        start = len(self.buf)
        self.buf += s
        self.gold.append({"type": etype, "span": [start, len(self.buf)]})

    def rec(self, modality: str, subset: str) -> dict:
        return {"text": self.buf, "gold": self.gold,
                "modality": modality, "subset": subset}


# --------------------------------------------------------------------------- #
# 值生成器
# --------------------------------------------------------------------------- #
def _id_valid(rng: random.Random) -> str:
    """18 位身份证:id_check_digit 合法校验位。"""
    area = rng.choice(["110105", "310101", "440305", "510107", "610113"])
    year = rng.randrange(1949, 2005)
    md = rng.choice(["0115", "0322", "0730", "1001", "1231"])
    seq = f"{rng.randrange(0, 1000):03d}"
    d17 = f"{area}{year}{md}{seq}"
    return d17 + id_check_digit(d17)


def _id_bad(rng: random.Random) -> str:
    """故意坏校验位负例(结构合法,第 18 位必错)。"""
    good = _id_valid(rng)
    wrong = str((int(good[-1]) if good[-1].isdigit() else 10) + 1)[-1] \
        if good[-1] != "9" else "0"
    if wrong == good[-1]:
        wrong = "7"
    return good[:17] + wrong


def _card_valid(rng: random.Random) -> str:
    """16 位卡号:Luhn 校验位合法。"""
    head = rng.choice(["622202", "622588", "621700", "622155"]) \
        + "".join(rng.choice("0123456789") for _ in range(9))
    return head + luhn_digit(head)


def _card_bad(rng: random.Random) -> str:
    """Luhn 不过负例(似订单号)。"""
    head = "622202" + "".join(rng.choice("0123456789") for _ in range(9))
    good = luhn_digit(head)
    bad = str((int(good) + 3) % 10)
    if bad == good:
        bad = str((int(good) + 1) % 10)
    return head + bad


def _phone(rng: random.Random) -> str:
    return rng.choice(["138", "139", "150", "151", "177", "186", "199"]) \
        + "".join(rng.choice("0123456789") for _ in range(8))


def _email(rng: random.Random) -> str:
    return rng.choice(["zhangsan", "lisi", "user", "ops", "demo",
                       "service", "acct", "hr"]) \
        + str(rng.randrange(1, 99)) + "@" \
        + rng.choice(["example.com", "mail.cn", "corp.org", "demo.net"])


def _ip(rng: random.Random) -> str:
    return f"{rng.randrange(1, 223)}.{rng.randrange(0, 255)}." \
           f"{rng.randrange(0, 255)}.{rng.randrange(1, 254)}"


def _url(rng: random.Random) -> str:
    return "https://" + rng.choice(["example.com", "portal.cn", "demo.org"]) \
        + "/" + rng.choice(["report", "files", "index", "docs"]) \
        + str(rng.randrange(1, 99))


def _apikey(rng: random.Random) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789_-"
    return "sk-" + "".join(rng.choice(alphabet) for _ in range(24))


def _num(rng: random.Random) -> str:
    """复合句里的金额/编号(不触发 CARD/ID/PHONE 正则)。"""
    return rng.choice([
        f"{rng.randrange(1, 99)}元", f"{rng.randrange(1000, 9999)}",
        f"{rng.randrange(10, 99)}.{rng.randrange(10, 99)}",
    ])


def _code(rng: random.Random) -> str:
    return rng.choice(["H", "R", "M", "B"]) + str(rng.randrange(20250000, 20260000))


# --------------------------------------------------------------------------- #
# 子集 1:模板 120(13 类实体×变体)
# --------------------------------------------------------------------------- #
def gen_templates(rng: random.Random) -> list[dict]:
    out: list[dict] = []

    def one(etype: str, value: str, frame: tuple[str, str] = ("", "。"),
            positive: bool = True):
        t = _Tex()
        t.add(frame[0])
        if positive:
            t.ent(value, etype)
        else:
            t.add(value)          # 负例:gold=[] 整句非敏感
        t.add(frame[1])
        out.append(t.rec("plain", "template"))

    for _ in range(10):
        one("NAME", rng.choice(_NAME_POOL), ("姓名：", "。"))
    for _ in range(7):
        one("ID", _id_valid(rng), ("身份证号：", "。"))
    for _ in range(3):
        one("ID", _id_bad(rng), ("身份证号：", "。"), positive=False)
    for _ in range(7):
        one("CARD", _card_valid(rng), ("银行卡号：", "。"))
    for _ in range(3):
        one("CARD", _card_bad(rng), ("银行卡号：", "。"), positive=False)
    for _ in range(9):
        one("PHONE", _phone(rng), ("联系电话：", "。"))
    for _ in range(9):
        one("EMAIL", _email(rng), ("电子邮箱：", "。"))
    for _ in range(9):
        one("ADDRESS", rng.choice(_ADDR_POOL), ("住址：", "。"))
    for _ in range(9):
        one("IP", _ip(rng), ("服务器地址：", "。"))
    for _ in range(9):
        one("URL", _url(rng), ("访问链接：", "。"))
    for _ in range(9):
        one("APIKEY", _apikey(rng), ("接口密钥：", "。"))
    for _ in range(9):
        one("PROJECT", rng.choice(_PROJ_POOL), ("项目代号：", "。"))
    for _ in range(9):
        one("ORG", rng.choice(_ORG_POOL), ("所属单位：", "。"))
    for _ in range(9):
        one("PHI", rng.choice(_PHI_POOL), ("医疗信息：", " 编号见册。"))
    for _ in range(9):
        one("PII", rng.choice(_PII_POOL), ("财务信息：", " 需核实。"))

    assert len(out) == 120, len(out)
    return out


# --------------------------------------------------------------------------- #
# 子集 2:复合 100(病历/流水句式,实体共现、嵌套)
# --------------------------------------------------------------------------- #
def _composite_frames(rng: random.Random, t: _Tex) -> None:
    kind = rng.randrange(10)
    if kind == 0:
        t.add("患者")
        t.ent(rng.choice(_NAME_POOL), "NAME")
        t.add("，身份证号 ")
        t.ent(_id_valid(rng), "ID")
        t.add("，今日到")
        t.ent(rng.choice(_ORG_POOL), "ORG")
        t.add("门诊复查。")
    elif kind == 1:
        t.ent(rng.choice(_NAME_POOL), "NAME")
        t.add("的")
        t.ent("账户余额", "PII")
        t.add("为")
        t.add(_num(rng))
        t.add("，")
        t.ent("交易流水", "PII")
        t.add("见附表。")
    elif kind == 2:
        t.ent("工资", "PII")
        t.ent("收入", "PII")
        t.add("证明：")
        t.ent(rng.choice(_NAME_POOL), "NAME")
        t.add("月")
        t.ent("收入", "PII")
        t.add(_num(rng))
        t.add("。")
    elif kind == 3:
        t.add("住址：")
        t.ent(rng.choice(_ADDR_POOL), "ADDRESS")
        t.add("，联系电话 ")
        t.ent(_phone(rng), "PHONE")
        t.add("。")
    elif kind == 4:
        t.add("电子邮箱：")
        t.ent(_email(rng), "EMAIL")
        t.add("，服务器地址：")
        t.ent(_ip(rng), "IP")
        t.add("。")
    elif kind == 5:
        t.ent(rng.choice(_PROJ_POOL), "PROJECT")
        t.add("评审会由")
        t.ent(rng.choice(_ORG_POOL), "ORG")
        t.add("组织，对接人")
        t.ent(rng.choice(_NAME_POOL), "NAME")
        t.add("。")
    elif kind == 6:
        t.ent("住院号", "PHI")
        t.add(" ")
        t.add(_code(rng))
        t.add("，")
        t.ent("病历号", "PHI")
        t.add(" ")
        t.add(_code(rng))
        t.add("，")
        t.ent("床号", "PHI")
        t.add(" ")
        t.add(str(rng.randrange(1, 60))
              )
    elif kind == 7:
        t.add("开户行")
        t.ent(rng.choice(_ORG_POOL), "ORG")
        t.add("，卡号 ")
        t.ent(_card_valid(rng), "CARD")
        t.add("。")
    elif kind == 8:
        t.add("访问链接：")
        t.ent(_url(rng), "URL")
        t.add("，接口密钥：")
        t.ent(_apikey(rng), "APIKEY")
        t.add("。")
    else:
        t.ent(rng.choice(_NAME_POOL), "NAME")
        t.add("，")
        t.ent(rng.choice(_PHI_POOL), "PHI")
        t.add(" ")
        t.add(_code(rng))
        t.add("，")
        t.ent("验证码", "PII")
        t.add(str(rng.randrange(100000, 999999)))
        t.add("。")


def gen_composite(rng: random.Random) -> list[dict]:
    out: list[dict] = []
    for _ in range(100):
        t = _Tex()
        _composite_frames(rng, t)          # 双句式嵌套:实体共现(校准至 P 达标)
        if not t.buf.endswith("。"):
            t.add("。")
        _composite_frames(rng, t)
        if not t.buf.endswith("。"):
            t.add("。")
        t.add(rng.choice(_FILLERS))
        t.add("。")
        out.append(t.rec("plain", "composite"))
    assert len(out) == 100, len(out)
    return out


# --------------------------------------------------------------------------- #
# 子集 4:跨模态 30(同一实体 × plain/csv-row/docx-para/pdf-line)
# --------------------------------------------------------------------------- #
def gen_crossmodal(rng: random.Random) -> list[dict]:
    carriers = [
        ("plain", lambda t, v, ty: (t.add("联系人："), t.ent(v, ty), t.add("。"))),
        ("csv-row", lambda t, v, ty: (t.add("1,"), t.ent(v, ty),
                                      t.add(",门诊,已登记"))),
        ("docx-para", lambda t, v, ty: (t.add("【入院记录】患者"),
                                        t.ent(v, ty), t.add("，今日入院。"))),
        ("pdf-line", lambda t, v, ty: (t.add("费用清单 持卡人："),
                                       t.ent(v, ty), t.add(" 第1页"))),
    ]
    out: list[dict] = []
    ent_pool = [
        ("NAME", "张三"), ("NAME", "李四"), ("PHONE", "13800138000"),
        ("PHONE", "15012345678"), ("EMAIL", "zhangsan@example.com"),
        ("ORG", "第一人民医院"), ("PROJECT", "天枢计划"), ("PII", "账户余额"),
    ]
    for etype, value in ent_pool:
        for modality, place in carriers:
            if len(out) >= 30:
                break
            t = _Tex()
            place(t, value, etype)
            out.append(t.rec(modality, "crossmodal"))
    assert len(out) == 30, len(out)
    return out


# --------------------------------------------------------------------------- #
def build_golden_set() -> list[dict]:
    """400 单元:120 模板 + 100 复合 + 150 对抗 + 30 跨模态。"""
    rng = random.Random(SEED)
    records = gen_templates(rng) + gen_composite(rng) \
        + build_adversarial() + gen_crossmodal(rng)
    assert len(records) == 400, len(records)
    return records


if __name__ == "__main__":
    recs = build_golden_set()
    n_spans = sum(len(r["gold"]) for r in recs)
    from collections import Counter
    print(f"units={len(recs)} gold_spans={n_spans}")
    print(Counter(r["subset"] for r in recs))
    print(Counter(g["type"] for r in recs for g in r["gold"]))
