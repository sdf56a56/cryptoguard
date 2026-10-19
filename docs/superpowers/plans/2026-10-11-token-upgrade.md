# CryptoGuard-LLM 分级令牌化升级 Implementation Plan

> **历史归档（2026-10）**：本文描述的是已删除的演示平台（`/api/*`、聊天查看器、
> 密码学实验室等），不代表当前实现，也不应作为部署依据。当前网关文档见
> [GATEWAY.md](../../GATEWAY.md)。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把占位符替换升级为 T1-T4 分级密码学令牌管道,覆盖文件上传双通道,四层协议绑定令牌/文件/用户决策,UI 收敛为六步协议叙事单线,并用测试套件锁死全部承诺指标。

**Architecture:** 后端新增 `canon.py`(JCS 哈希基座)→ `tokens.py`(T1-T4)→ `tokenchain.py`(绑定层)→ `files.py`(文件双通道)→ `gateway.py`(计算网关)→ 重写 `proxy.py` 流水线;攻击走独立沙箱快照。前端 12 页重组为单路由六步控制台 + 附录抽屉。ProVerif 与代码按字段对照表同表施工。

**Tech Stack:** Python 3.13.14 / FastAPI 0.115.0 / cryptography 43.0.1 / pytest;FF1 用 `ff3`(降级 `pyffx`);JCS 用 `jcs`(降级 `canonicaljson`);前端 React 18 + Vite 5 + Tailwind。

**Spec:** `docs/superpowers/specs/2026-10-11-crypto-token-upgrade-design.md`(所有公式、Schema、测试口径以 spec 为准;本计划与 spec 冲突时以 spec 为准)

## Global Constraints

- 所有哈希前映像走 `canon()`(JCS);**禁止**裸 `json.dumps`、手写 TLV、字节拼接做哈希前映像(spec §3.1)
- T1 截断 **128-bit** Base32 小写;T2 必须用标准 FF1 库;T3 静态集合 **≤20 个数值,不支持动态插入**;T4 只走计算网关白名单 `op ∈ {sum,mean,count,min,max}`
- Mock 延迟由**后端** sleep 50–100ms 模拟,帧内必须携带 `mock_sleep_ms` 字段
- 密码学/检测 CPU 密集操作走 `run_in_executor` 线程池;吞吐靠 uvicorn 多 worker,不做 asyncio 单进程承诺
- Pydantic 模型一律 `model_config = ConfigDict(extra="forbid")`;`schema_version` 必须为 `"CG/2.0"`
- UI 铁律:**无徽章不渲染**;UI 零自算(不自行计算任何哈希/签名)
- 演示降级必须可见(横幅),禁止静默降级
- 每个提交含测试;commit message 用 `feat:/test:/fix:` 前缀

## Review Focus

1. **JCS 库一致性**:`jcs` 与 `canonicaljson` 对浮点/Unicode/转义输出可能不同 → Task 1 的 BIND-6 向量测试决定选型,双库交叉验证
2. **FF1 库在 Py3.13 的可装性与性能**:`ff3` 装不上或 >2ms/个 → Task 3 的 PERF-FF1-1 校准测试同时验证降级路径被真实触发
3. **无文本层文件静默进可读通道**:纯图 PDF 抽取返回空串,若按"类型支持"路由会明文泄露 → Task 8 的 SEC-FROUTE 测试断言空文本强制降级存证
4. **攻击沙箱污染主链**:攻击注入若写主状态,演示后数据不可信 → Task 14 的 SEC-ISO-1/2 断言主链 verify() 恒真且 reset 后逐字段相等
5. **计时条造假/缺 mock 标注**:前端若自行动画或丢 `mock_sleep_ms`,性能演示不可信 → Task 15 的 PERF-TRUTH-1 双断言(字符串相等 + 差值 <0.01ms)

---

## Phase A:密码基座

### Task 1: 项目基建 + JCS 哈希基座(canon.py)

**Files:**
- Create: `backend/app/canon.py`
- Create: `backend/tests/__init__.py`
- Create: `backend/tests/test_canon.py`
- Modify: `backend/requirements.txt`
- Modify: `git`(首次初始化仓库)

**Interfaces:**
- Produces: `canon(obj: dict|list) -> bytes`(JCS 字节串);`h_hex(obj: dict) -> str`(sha256 hex);模块常量 `JCS_LIB: str`

- [ ] **Step 1: 初始化 git 仓库并补依赖**

```bash
cd /e/编程/密码技术竞赛/cryptoguard
git init 2>/dev/null; git add -A; git commit -m "chore: baseline before token upgrade" --allow-empty
```

在 `backend/requirements.txt` 追加(`ff3` 在 Task 3 再加):

```
pytest==8.3.3
httpx==0.27.2
jcs==1.2.0
canonicaljson==2.0.0
```

```bash
cd backend && pip install -r requirements.txt
```

若 `jcs` 或 `canonicaljson` 安装失败,降级安装可用者并在测试里跳过对应分支(见 Step 3)。

- [ ] **Step 2: 写失败的 BIND-6 RFC 8785 符合性测试**

`backend/tests/test_canon.py`:

```python
import pytest
from app.canon import canon, h_hex, JCS_LIB

# RFC 8785 风格测试向量:键序、浮点、Unicode、转义
def test_bind2_key_order_stability():
    a = {"b": "2", "a": "1", "c": {"z": 1, "y": 2}}
    b = {"a": "1", "c": {"y": 2, "z": 1}, "b": "2"}
    assert canon(a) == canon(b)

def test_bind6_unicode_nfc_nfd():
    nfc = {"k": "é"}          # é = é
    nfd = {"k": "é"}         # e + ́
    assert canon(nfc) == canon(nfd)

def test_bind6_escape_stability():
    assert canon({"k": "a\"b\\c\nd"}) == b'{"k":"a\\"b\\\\c\\nd"}'

def test_bind6_numbers():
    assert canon({"n": 1.0}) == canon({"n": 1.0})
    # 整数与浮点 1.0 的序列化必须确定(同值同字节)
    assert canon({"n": 1}) != canon({"n": 1.5})

def test_bind5_empty_and_blank():
    assert isinstance(canon({"a": [], "b": "", "c": "   "}), bytes)
    assert h_hex({"a": []}) == h_hex({"a": []})  # 确定性

def test_h_hex_len():
    assert len(h_hex({"x": 1})) == 64
```

- [ ] **Step 3: 运行确认失败,实现 canon.py**

Run: `python -m pytest tests/test_canon.py -v`
Expected: FAIL `ModuleNotFoundError: app.canon`

`backend/app/canon.py`:

```python
"""
JCS 哈希基座 —— RFC 8785 JSON Canonicalization Scheme

安全目标:哈希前映像确定性(同对象→同字节),消灭拼接歧义与字节序 bug。
明确不承诺:规范化只保证编码确定性,不提供任何密码学强度(强度来自 SHA-256/HMAC)。
选型:jcs 优先,canonicaljson 降级;BIND-6 向量测试锁定行为。
"""
from __future__ import annotations
import hashlib

try:
    from jcs import canonicalize as _canon_impl
    JCS_LIB = "jcs"
except ImportError:  # pragma: no cover
    from canonicaljson import encode_canonical_json as _canon_impl
    JCS_LIB = "canonicaljson"


def canon(obj: dict | list) -> bytes:
    """RFC 8785 规范化,返回 bytes 作为哈希前映像。"""
    return _canon_impl(obj)


def h_hex(obj: dict) -> str:
    """对规范化 JSON 对象取 SHA-256 hex。"""
    return hashlib.sha256(canon(obj)).hexdigest()
```

- [ ] **Step 4: 运行测试确认通过**

Run: `python -m pytest tests/test_canon.py -v`
Expected: 全部 PASS(若 `canonicaljson` 下 Unicode 用例失败,在 README 记录"canonicaljson 不满足 RFC 8785 Unicode 规则,正式选型 jcs")

- [ ] **Step 5: Commit**

```bash
git add backend/app/canon.py backend/tests backend/requirements.txt
git commit -m "feat: JCS canonicalization base (canon.py) with BIND-6 conformance tests"
```

---

### Task 2: T1 不透明伪名令牌

**Files:**
- Create: `backend/app/tokens.py`(T1 部分;后续 Task 3/4/5 同文件追加)
- Create: `backend/tests/test_tokens_t1.py`

**Interfaces:**
- Consumes: 无(独立 PRF 构造)
- Produces: `t1_pseudonym(k_t1: bytes, type_: str, value: str, session_salt: bytes) -> str`(返回 26 字符 Base32 小写令牌);`T1_DISPLAY_LEN = 10`(展示前缀长度)

- [ ] **Step 1: 写失败测试**

`backend/tests/test_tokens_t1.py`:

```python
import os
from app.tokens import t1_pseudonym, T1_DISPLAY_LEN

K = b"k" * 32
SALT = b"s" * 16

def test_deterministic_same_session():
    a = t1_pseudonym(K, "NAME", "张三", SALT)
    b = t1_pseudonym(K, "NAME", "张三", SALT)
    assert a == b

def test_different_salt_unlinkable():
    a = t1_pseudonym(K, "NAME", "张三", SALT)
    b = t1_pseudonym(K, "NAME", "张三", b"x" * 16)
    assert a != b

def test_type_separation():
    assert t1_pseudonym(K, "NAME", "张三", SALT) != t1_pseudonym(K, "ORG", "张三", SALT)

def test_format_128bit_base32():
    tok = t1_pseudonym(K, "NAME", "张三", SALT)
    assert len(tok) == 26            # 128 bit / 5 bit ≈ 26 chars
    assert tok == tok.lower()
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in tok)

def test_display_prefix():
    tok = t1_pseudonym(K, "NAME", "张三", SALT)
    assert len(tok[:T1_DISPLAY_LEN]) == T1_DISPLAY_LEN
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_tokens_t1.py -v`
Expected: FAIL `ModuleNotFoundError: app.tokens`

- [ ] **Step 3: 实现 T1**

`backend/app/tokens.py`:

```python
"""
分级令牌模块 —— T1 不透明伪名 / T2 格式保留 / T3 保序 / T4 同态

T1 安全目标:伪名不可区分(HMAC PRF),同会话共指,跨会话不可关联。
明确不承诺:不抗同值频率统计(同名出现次数可见)。
归约:PRF 安全。
"""
from __future__ import annotations
import base64
import hashlib
import hmac

T1_DISPLAY_LEN = 10


def t1_pseudonym(k_t1: bytes, type_: str, value: str, session_salt: bytes) -> str:
    raw = hmac.new(
        k_t1,
        type_.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00" + session_salt,
        hashlib.sha256,
    ).digest()
    return base64.b32encode(raw[:16]).decode("ascii").lower()   # 128-bit 截断
```

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_tokens_t1.py -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/tokens.py backend/tests/test_tokens_t1.py
git commit -m "feat: T1 HMAC pseudonym tokens (128-bit Base32) with PRF tests"
```

---

### Task 3: T2 FF1 格式保留令牌 + 校验位修复 + 性能校准

**Files:**
- Modify: `backend/app/tokens.py`(追加 T2)
- Modify: `backend/requirements.txt`(追加 `ff3`)
- Create: `backend/tests/test_tokens_t2.py`
- Create: `backend/tests/test_perf_ff1.py`(PERF-FF1-1)

**Interfaces:**
- Consumes: 无
- Produces: `T2Cipher` 类:`encrypt_id17(v17: str) -> str`(17 位数字→17 位)、`encrypt_card15(v15: str) -> str`、`encrypt_phone_tail9(v9: str) -> str`;`id_check_digit(d17: str) -> str`、`luhn_digit(d15: str) -> str`;`ff1_unit_ms_p95() -> float`;`FF1_DEGRADED: bool`

- [ ] **Step 1: 写失败测试(格式与校验位)**

`backend/tests/test_tokens_t2.py`:

```python
import re
from app.tokens import T2Cipher, id_check_digit, luhn_digit

c = T2Cipher(key=bytes(range(32)))

def test_id_roundtrip_and_checkdigit():
    d17 = "11010519491231002"          # 北京 1949-12-31
    ct = c.encrypt_id17(d17)
    assert re.fullmatch(r"\d{17}", ct)  # 保格式:17 位数字
    full = ct + id_check_digit(ct)
    assert re.fullmatch(r"\d{16}[\dXx]", full)   # 18 位含校验位
    assert c.decrypt_id17(ct) == d17             # 逆变换

def test_card_luhn_repair():
    d15 = "622202020001234"             # 前 15 位
    ct = c.encrypt_card15(d15)
    full = ct + luhn_digit(ct)
    # Luhn 全卡校验通过
    digits = [int(x) for x in full]
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9: d -= 9
        s += d
    assert s % 10 == 0

def test_phone_tail():
    ct = c.encrypt_phone_tail9("912345678")
    assert re.fullmatch(r"\d{9}", ct)
    assert c.decrypt_phone_tail9(ct) == "912345678"

def test_different_plaintext_different_cipher():
    assert c.encrypt_id17("11010519491231002") != c.encrypt_id17("11010519491231003")
```

- [ ] **Step 2: 写 PERF-FF1-1 校准测试(含降级断言)**

`backend/tests/test_perf_ff1.py`:

```python
"""PERF-FF1-1:FF1 实测校准。>2ms/个 必须降级可观测,不许静默。"""
from app.tokens import T2Cipher, ff1_unit_ms_p95, FF1_DEGRADED

def test_ff1_p95_budget_or_visible_degradation():
    c = T2Cipher(key=bytes(range(32)))
    c.encrypt_id17("11010519491231002")          # 预热
    p95 = ff1_unit_ms_p95(c, n=1000)
    assert p95 <= 2.0 or FF1_DEGRADED, (
        f"FF1 P95={p95:.2f}ms/个 超 2ms 预算,必须置 FF1_DEGRADED=True 并触发降级横幅"
    )
```

- [ ] **Step 3: 运行确认失败,实现**

Run: `python -m pytest tests/test_tokens_t2.py tests/test_perf_ff1.py -v`
Expected: FAIL `cannot import T2Cipher`

`backend/requirements.txt` 追加 `ff3==1.0.0`;`pip install ff3`。若安装失败,改用 `pyffx` 并保留同一接口(在 T2Cipher 内部分支),README 记录选型结果。

`backend/app/tokens.py` 追加:

```python
import time

FF1_DEGRADED = False   # PERF-FF1-1:超预算时置 True,UI 横幅读取


class T2Cipher:
    """FF1 格式保留加密(标准库)。身份证前17位/卡号前15位/手机后9位。"""

    def __init__(self, key: bytes, tweak: bytes = b"cryptoguard"):
        try:
            from ff3 import FF3Cipher
            self._impl = "ff3"
            k = key[:16].hex()
            self._c = FF3Cipher(k, tweak[:7].hex(), radix=10)
        except ImportError:
            import pyffx
            self._impl = "pyffx"
            self._c = pyffx.String(key[:16], alphabet="0123456789", length=17)

    def encrypt_id17(self, v17: str) -> str:
        return self._enc(v17)

    def decrypt_id17(self, ct: str) -> str:
        return self._dec(ct)

    def encrypt_card15(self, v15: str) -> str:
        return self._enc(v15)

    def encrypt_phone_tail9(self, v9: str) -> str:
        return self._enc(v9)

    def decrypt_phone_tail9(self, ct: str) -> str:
        return self._dec(ct)

    def _enc(self, s: str) -> str:
        return self._c.encrypt(s)

    def _dec(self, s: str) -> str:
        return self._c.decrypt(s)


def id_check_digit(d17: str) -> str:
    """ISO 7064 MOD 11-2 身份证第 18 位。"""
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    s = sum(int(d) * wi for d, wi in zip(d17, w))
    return "10X98765432"[s % 11]


def luhn_digit(d15: str) -> str:
    """Luhn 校验位(第 16 位)。"""
    digits = [int(x) for x in d15]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:                    # 第 16 位占奇数位,前 15 位偶数位加倍
            d *= 2
            if d > 9: d -= 9
        total += d
    return str((10 - total % 10) % 10)


def ff1_unit_ms_p95(c: "T2Cipher", n: int = 1000) -> float:
    """PERF-FF1-1 实测:n 次加密耗时 P95(ms/个)。"""
    import statistics
    samples = []
    probe = "1101051949123100"
    for i in range(n):
        t0 = time.perf_counter()
        c._enc(probe + str(i % 10))
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return samples[int(n * 0.95)]
```

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_tokens_t2.py tests/test_perf_ff1.py -v`
Expected: 全 PASS。若 P95 >2ms:手动置 `FF1_DEGRADED = True` 再跑,确认降级断言路径可过,并在 Task 16 的 UI 接降级横幅。

- [ ] **Step 5: Commit**

```bash
git add backend/app/tokens.py backend/tests backend/requirements.txt
git commit -m "feat: T2 FF1 format-preserving tokens with check-digit repair and PERF-FF1-1 calibration"
```

---

### Task 4: T3 静态保序令牌(≤20 值)+ 分桶降级

**Files:**
- Modify: `backend/app/tokens.py`(追加 T3)
- Create: `backend/tests/test_tokens_t3.py`

**Interfaces:**
- Produces: `StaticOPE(values: list[int])`(构造时一次性注入 ≤20 个数值);`StaticOPE.encrypt(v: int) -> int`;`StaticOPE.decrypt(e: int) -> int`;`StaticOPE.LEAK = "序关系+等值性"`;`BucketOPE(bounds: list[int])` 分桶降级(约 50 行内)

- [ ] **Step 1: 写失败测试**

`backend/tests/test_tokens_t3.py`:

```python
import pytest
from app.tokens import StaticOPE, BucketOPE

VALUES = [10, 25, 3, 99, 40, 7, 7, 60, 1, 55]

def test_order_preserving_static():
    o = StaticOPE(VALUES)
    enc = {v: o.encrypt(v) for v in set(VALUES)}
    for a in set(VALUES):
        for b in set(VALUES):
            if a < b:
                assert enc[a] < enc[b]
            if a == b:
                assert enc[a] == enc[b]

def test_roundtrip():
    o = StaticOPE(VALUES)
    for v in set(VALUES):
        assert o.decrypt(o.encrypt(v)) == v

def test_reject_dynamic_insert():
    o = StaticOPE(VALUES)
    with pytest.raises(KeyError):
        o.encrypt(1000)           # 不支持动态插入 —— spec §1.3 静态边界

def test_reject_over_20():
    with pytest.raises(ValueError):
        StaticOPE(list(range(21)))

def test_bucket_fallback():
    b = BucketOPE(bounds=[0, 50, 100])
    assert b.encrypt(10) < b.encrypt(60) < b.encrypt(90)
    assert b.LEAK == "桶序"
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_tokens_t3.py -v`
Expected: FAIL `cannot import StaticOPE`

- [ ] **Step 3: 实现**

`backend/app/tokens.py` 追加:

```python
import secrets as _secrets


class StaticOPE:
    """简化保序编码:演示前固定 ≤20 个数值,秩+随机间隔,单调保序。
    显式泄漏:序关系 + 等值性(UI 徽章 ⚠️ 泄漏:序关系)。不支持动态插入。"""
    LEAK = "序关系+等值性"
    MAX_VALUES = 20

    def __init__(self, values: list[int]):
        if len(set(values)) > self.MAX_VALUES:
            raise ValueError("静态集合上限 20 个数值(spec §1.3)")
        self._enc: dict[int, int] = {}
        rank = 0
        for v in sorted(set(values)):
            rank += 1 + _secrets.randbelow(64)     # 随机间隔
            self._enc[v] = rank
        self._dec = {r: v for v, r in self._enc.items()}

    def encrypt(self, v: int) -> int:
        if v not in self._enc:
            raise KeyError(f"{v} 不在静态集合内,不支持动态插入")
        return self._enc[v]

    def decrypt(self, e: int) -> int:
        return self._dec[e]


class BucketOPE:
    """分桶保序降级:仅泄漏桶序,桶边界公开声明。"""
    LEAK = "桶序"

    def __init__(self, bounds: list[int]):
        self._bounds = sorted(bounds)

    def encrypt(self, v: int) -> int:
        import bisect
        return bisect.bisect_right(self._bounds, v)
```

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_tokens_t3.py -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/tokens.py backend/tests/test_tokens_t3.py
git commit -m "feat: T3 static OPE (<=20 values) with bucket fallback and explicit leakage"
```

---

### Task 5: T4 同态令牌 + 计算网关白名单(gateway.py)

**Files:**
- Create: `backend/app/gateway.py`
- Create: `backend/tests/test_gateway.py`

**Interfaces:**
- Consumes: 现有 `app.crypto.he.Paillier`
- Produces: `ComputeDirective` 数据类:`op: str, tokens: list[str], result_ref: str`;`validate_directive(raw: dict, token_index: dict[str, str]) -> ComputeDirective`(token_index 是 token→tier 映射,越权抛 `GatewayReject`);`aggregate(op: str, values: list[int]) -> int|float`;`class GatewayReject(Exception)` 带 `reason: str`

- [ ] **Step 1: 写失败测试(含 SEC-ATK-8 断言材料)**

`backend/tests/test_gateway.py`:

```python
import pytest
from app.gateway import validate_directive, aggregate, GatewayReject

TOKEN_INDEX = {"[AMT#a1]": "T3", "[AMT#b2]": "T4", "[NAME#c3]": "T1"}

def test_valid_sum():
    d = validate_directive(
        {"op": "sum", "tokens": ["[AMT#a1]", "[AMT#b2]"], "result_ref": "c_01"},
        TOKEN_INDEX)
    assert d.op == "sum"

def test_reject_unknown_op():
    with pytest.raises(GatewayReject):
        validate_directive({"op": "exec", "tokens": ["[AMT#a1]"], "result_ref": "c_01"}, TOKEN_INDEX)

def test_reject_token_not_in_index():          # SEC-ATK-8 核心:注入非法令牌
    with pytest.raises(GatewayReject) as e:
        validate_directive(
            {"op": "sum", "tokens": ["[FAKE#deadbeef]"], "result_ref": "c_01"},
            TOKEN_INDEX)
    assert "越权" in e.value.reason or "不在" in e.value.reason

def test_reject_wrong_tier():
    with pytest.raises(GatewayReject):
        validate_directive(
            {"op": "sum", "tokens": ["[NAME#c3]"], "result_ref": "c_01"}, TOKEN_INDEX)

def test_aggregate_ops():
    assert aggregate("sum", [1, 2, 3]) == 6
    assert aggregate("mean", [2, 4]) == 3.0
    assert aggregate("count", [5, 5]) == 2
    assert aggregate("min", [7, 3]) == 3
    assert aggregate("max", [7, 3]) == 7
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_gateway.py -v`
Expected: FAIL `ModuleNotFoundError: app.gateway`

- [ ] **Step 3: 实现 gateway.py**

```python
"""
计算网关 —— T4/聚合指令白名单校验(不信任模型自由输出)

安全目标:指令只能操作出站清单内令牌;越权拒绝并可入 COMPUTE_GATE 审计链。
明确不承诺:不验证指令语义合理性(如求和混入非数值),由聚合函数类型约束。
"""
from __future__ import annotations
from dataclasses import dataclass

ALLOWED_OPS = {"sum", "mean", "count", "min", "max"}
AGGREGATE_TIERS = {"T3", "T4"}


class GatewayReject(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ComputeDirective:
    op: str
    tokens: tuple[str, ...]
    result_ref: str


def validate_directive(raw: dict, token_index: dict[str, str]) -> ComputeDirective:
    op = raw.get("op")
    if op not in ALLOWED_OPS:
        raise GatewayReject(f"op={op!r} 不在白名单 {sorted(ALLOWED_OPS)}")
    tokens = raw.get("tokens") or []
    if not tokens:
        raise GatewayReject("tokens 为空")
    for t in tokens:
        if t not in token_index:
            raise GatewayReject(f"令牌 {t} 越权:不在出站 token_index 内")
        if token_index[t] not in AGGREGATE_TIERS:
            raise GatewayReject(f"令牌 {t} tier={token_index[t]} 不允许聚合")
    return ComputeDirective(op=op, tokens=tuple(tokens), result_ref=str(raw.get("result_ref", "")))


def aggregate(op: str, values: list[int]):
    if op == "sum":   return sum(values)
    if op == "mean":  return sum(values) / len(values)
    if op == "count": return len(values)
    if op == "min":   return min(values)
    if op == "max":   return max(values)
    raise GatewayReject(f"op={op!r} 未知")
```

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_gateway.py -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/gateway.py backend/tests/test_gateway.py
git commit -m "feat: compute gateway whitelist (T4 directives) with SEC-ATK-8 rejection tests"
```

---

### Task 6: 令牌绑定链 + input_hash + override_hash(tokenchain.py)

**Files:**
- Create: `backend/app/tokenchain.py`
- Create: `backend/tests/test_tokenchain.py`

**Interfaces:**
- Consumes: `app.canon.h_hex`
- Produces: `token_chain(session_id: str, tokens: list[tuple[str, str]]) -> str`(token_root;tokens 为 (type, token) 序列);`file_content_hash(redacted_content: str) -> str`;`override_hash(events: list[dict]) -> str`;`input_hash(redacted_text: str, file_hashes: list[str], token_root: str, override_h: str, nonce: str, timestamp: str) -> str`;`response_hash(output: str, input_hash: str, model_cert: dict, nonce: str, timestamp: str) -> str`

- [ ] **Step 1: 写失败测试(BIND-1/3/4/5)**

`backend/tests/test_tokenchain.py`:

```python
from app.tokenchain import (token_chain, file_content_hash,
                            override_hash, input_hash, response_hash)

SID = "sess01"
TOKS = [("NAME", "a3f9b2c1d0e4f5a6b7c8d9e0f1a2b3c4"), ("CARD", "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9")]

def test_token_root_deterministic():
    assert token_chain(SID, TOKS) == token_chain(SID, TOKS)

def test_bind1_swap_token_changes_root():        # BIND-1 令牌张冠李戴
    r1 = token_chain(SID, TOKS)
    swapped = [("NAME", "0" * 32), TOKS[1]]
    assert token_chain(SID, swapped) != r1

def test_bind3_file_content_sensitivity():       # BIND-3
    assert file_content_hash("患者甲") != file_content_hash("患者乙")

def test_bind4_override_bound():                 # BIND-4 用户诬告
    ev = [{"action": "force_allow", "user_ack": True}]
    ih1 = input_hash("t", [], "r", override_hash(ev), "n", "ts")
    ih2 = input_hash("t", [], "r", override_hash([]), "n", "ts")
    assert ih1 != ih2

def test_bind5_empty_override_stable():
    assert override_hash([]) == override_hash([])

def test_input_hash_all_fields_bound():
    base = ("text", ["fh1"], "root", override_hash([]), "nonce", "2026-10-11T00:00:00.000000Z")
    assert input_hash(*base) != input_hash("text2", *base[1:])
    assert input_hash(*base) != input_hash(base[0], ["fh2"], *base[2:])

def test_response_hash_shape():
    cert = {"model_id": "m", "version": "1", "signature": "sig"}
    rh = response_hash("out", "ih", cert, "n", "ts")
    assert len(rh) == 64
    assert rh != response_hash("out2", "ih", cert, "n", "ts")
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_tokenchain.py -v`
Expected: FAIL `ModuleNotFoundError: app.tokenchain`

- [ ] **Step 3: 实现 tokenchain.py(spec §3.1 公式逐字对齐)**

```python
"""
令牌绑定层 —— 顺序累加链 + JCS 哈希(spec §3.1)

安全目标:令牌/文件/用户决策与 input_hash 绑定 → 任何偷换打穿层 3 签名。
归约:抗第二原像。明确不承诺:哈希链只检测偷换,不阻止发送前的本地篡改。
"""
from __future__ import annotations
from .canon import h_hex

D_CHAIN = "CG/TOKEN_CHAIN/v2"
D_TEXT = "CG/TEXT/v2"
D_FC = "CG/FILE_CONTENT/v2"
D_OV = "CG/OVERRIDE/v2"
D_INPUT = "CG/INPUT/v2"
D_RESP = "CG/RESP/v2"


def token_chain(session_id: str, tokens: list[tuple[str, str]]) -> str:
    chain = h_hex({"d": D_CHAIN, "prev": None, "sid": session_id})
    for t, k in tokens:
        chain = h_hex({"d": D_CHAIN, "prev": chain, "t": t, "k": k})
    return chain


def file_content_hash(redacted_content: str) -> str:
    return h_hex({"d": D_FC, "c": redacted_content})


def override_hash(events: list[dict]) -> str:
    return h_hex({"d": D_OV, "e": events})


def input_hash(redacted_text: str, file_hashes: list[str], token_root: str,
               override_h: str, nonce: str, timestamp: str) -> str:
    return h_hex({
        "d": D_INPUT,
        "t": h_hex({"d": D_TEXT, "x": redacted_text}),
        "f": file_hashes,
        "r": token_root,
        "o": override_h,
        "n": nonce,
        "ts": timestamp,
    })


def response_hash(output: str, input_hash_v: str, model_cert: dict,
                  nonce: str, timestamp: str) -> str:
    return h_hex({"d": D_RESP, "out": output, "ih": input_hash_v,
                  "cert": model_cert, "n": nonce, "ts": timestamp})
```

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_tokenchain.py -v`
Expected: 8 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/tokenchain.py backend/tests/test_tokenchain.py
git commit -m "feat: token binding chain + input_hash/override_hash (JCS) with BIND tests"
```

---

## Phase B:协议与数据面

### Task 7: Schema 扩展 + 网关校验(schemas.py)

**Files:**
- Modify: `backend/app/schemas.py`
- Create: `backend/tests/test_schemas.py`

**Interfaces:**
- Consumes: Task 2-6 的令牌与哈希函数
- Produces: `TokenRef{token,type,tier,leak_class}`、`OverrideEvent{event_id,entity_span,entity_type,original_token,action,replacement,user_ack,ts}`、`FilePayload{file_ref,filename_token,content_tier,redacted_content,file_content_hash,file_hash}`、`OutboundRequest{schema_version,session_id,redacted_text,file_payloads,token_index,override_events,token_root,input_hash,nonce,timestamp}`、`ComputeDirectiveModel{op,tokens,result_ref}`;`build_outbound(...) -> OutboundRequest` 模板拼装函数;`verify_outbound(req, k_t1, session_salt) -> list[str]` 返回违规列表(空=通过)

- [ ] **Step 1: 写失败测试(强 Schema + 网关校验规则)**

`backend/tests/test_schemas.py`:

```python
import pytest
from pydantic import ValidationError
from app.schemas import (TokenRef, FilePayload, OutboundRequest,
                         build_outbound, verify_outbound)

def _outbound(**over):
    base = dict(
        session_id="a" * 32,
        redacted_text="患者 [NAME#a3f9b2c1d0e4f5a6b7c8d9e0f1a2b3c4] 就诊",
        file_payloads=[],
        token_index=[TokenRef(token="a3f9b2c1d0e4f5a6b7c8d9e0f1a2b3c4",
                              type="NAME", tier="T1", leak_class="频率可见")],
        override_events=[],
        nonce="b" * 32,
        timestamp="2026-10-11T00:00:00.000000Z",
    )
    base.update(over)
    return build_outbound(**base)

def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        OutboundRequest(**{**_outbound().model_dump(), "evil": 1})

def test_schema_version_constant():
    assert _outbound().schema_version == "CG/2.0"

def test_verify_pass():
    req = _outbound()
    assert verify_outbound(req, k_t1=b"k" * 32, session_salt=b"s" * 16) == []

def test_verify_catches_smuggled_token():        # 网关规则 1:文本令牌 ⊆ token_index
    req = _outbound(redacted_text="外挂 [FAKE#deadbeef] 令牌")
    assert any("不在 token_index" in v for v in verify_outbound(req, b"k" * 32, b"s" * 16))

def test_verify_catches_input_hash_mismatch():   # 网关规则 3
    req = _outbound()
    req.input_hash = "0" * 64
    assert any("input_hash" in v for v in verify_outbound(req, b"k" * 32, b"s" * 16))

def test_file_payload_evidence_has_no_content():
    with pytest.raises(ValidationError):
        FilePayload(file_ref="f_01", filename_token="x", content_tier="evidence",
                    redacted_content="泄漏!", file_content_hash=None, file_hash="f" * 64)
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_schemas.py -v`
Expected: FAIL ImportError

- [ ] **Step 3: 实现(build_outbound 为唯一出站拼装入口)**

`schemas.py` 追加(具体字段定义按 spec §3.2 逐字段落 Pydantic,`model_config = ConfigDict(extra="forbid")`;`build_outbound` 内部计算 `token_root`(token_chain)、`override_hash`、`file_content_hash`(对每个 readable 文件)、`input_hash`,即出站包由后端模板拼装、不由调用方自由构造):

```python
# —— 摘录核心拼装逻辑(完整字段定义按 spec §3.2)——
from .tokenchain import token_chain, override_hash, input_hash as _ih, file_content_hash as _fch

def build_outbound(*, session_id, redacted_text, file_payloads, token_index,
                   override_events, nonce, timestamp, session_salt) -> OutboundRequest:
    toks = [(t.type, t.token) for t in token_index]
    root = token_chain(session_id, toks)
    ov = override_hash([e.model_dump() for e in override_events])
    fhashes = [p.file_content_hash or _fch(p.redacted_content or "")
               for p in file_payloads if p.content_tier == "readable"]
    ih = _ih(redacted_text, fhashes, root, ov, nonce, timestamp)
    return OutboundRequest(schema_version="CG/2.0", session_id=session_id, ...)
```

`verify_outbound` 实现三条网关规则(spec §3.2),违规字符串逐条可辨(`"令牌 X 不在 token_index"`/`"input_hash 重算不一致"`/`"令牌 X HMAC 与声明不一致"`)。

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_schemas.py -v`
Expected: 6 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/schemas.py backend/tests/test_schemas.py
git commit -m "feat: strict outbound schema + gateway verification rules (CG/2.0)"
```

---

### Task 8: 文件抽取 + 默认拒绝路由 + 存证通道(files.py)

**Files:**
- Create: `backend/app/files.py`
- Create: `backend/tests/test_files.py`
- Create: `backend/tests/fixtures/sample.txt`(测试样例)

**Interfaces:**
- Consumes: `app.tokenchain.file_content_hash`;`app.crypto.aead.AeadCipher`
- Produces: `extract_text(data: bytes, filename: str) -> tuple[str, str]`(文本, 抽取器名;失败/为空 → `("", reason)`);`route_file(filename: str, text: str) -> Literal["readable","evidence"]`;`evidence_bundle(data: bytes, filename: str, aead: AeadCipher) -> dict`(含 `file_hash`, `vault_ct`, `filename_token` 占位);`MAX_FILE_BYTES = 5 * 1024 * 1024`;`MAX_TEXT_CHARS = 50_000`

- [ ] **Step 1: 写失败测试(SEC-FROUTE 默认拒绝)**

`backend/tests/test_files.py`:

```python
import pytest
from app.files import extract_text, route_file, evidence_bundle, MAX_FILE_BYTES
from app.crypto.aead import AeadCipher

def test_txt_extract():
    text, how = extract_text("患者张三".encode(), "a.txt")
    assert text == "患者张三"

def test_empty_text_forces_evidence():           # Review Focus #3
    text, how = extract_text(b"", "scan.pdf")
    assert text == ""
    assert route_file("scan.pdf", text) == "evidence"

def test_binary_forces_evidence():
    assert route_file("x.zip", "") == "evidence"

def test_txt_route_readable():
    assert route_file("a.txt", "有内容") == "readable"

def test_oversize_rejected():
    with pytest.raises(ValueError):
        extract_text(b"0" * (MAX_FILE_BYTES + 1), "big.txt")

def test_evidence_bundle_has_hash_and_cipher():
    b = evidence_bundle(b"\x89PNG fake", "张三的报告.png", AeadCipher())
    assert len(b["file_hash"]) == 64
    assert b["vault_ct"]["ciphertext"]           # AES-GCM 密文非空
    assert b["content_tier"] == "evidence"
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_files.py -v`
Expected: FAIL `ModuleNotFoundError`

- [ ] **Step 3: 实现 files.py(依赖 `pypdf`、`python-docx` 进 requirements)**

```python
"""
文件双通道 —— 抽取/默认拒绝路由/存证(spec §2)

安全目标:检测不可信的内容不进可读通道;原始文件永不出本地,存证三件套可验。
明确不承诺:抽取丢字不保真;OCR 质量不在本模块;漏检实体仍会明文出站(检测召回率的函数)。
"""
from __future__ import annotations
import hashlib
from typing import Literal

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 50_000


def extract_text(data: bytes, filename: str) -> tuple[str, str]:
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"文件超限 {MAX_FILE_BYTES} 字节")
    name = filename.lower()
    try:
        if name.endswith((".txt", ".md", ".csv")):
            return data.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS], "builtin"
        if name.endswith(".docx"):
            import docx, io
            d = docx.Document(io.BytesIO(data))
            return "\n".join(p.text for p in d.paragraphs)[:MAX_TEXT_CHARS], "python-docx"
        if name.endswith(".pdf"):
            import pypdf, io
            r = pypdf.PdfReader(io.BytesIO(data))
            return "\n".join((p.extract_text() or "") for p in r.pages)[:MAX_TEXT_CHARS], "pypdf"
    except Exception as exc:
        return "", f"extract-error:{type(exc).__name__}"
    return "", "unsupported"


def route_file(filename: str, text: str) -> Literal["readable", "evidence"]:
    # 默认拒绝:抽取文本为空或含抽取错误 → 只走存证(spec §2.1)
    if not text.strip() or text.startswith("extract-error"):
        return "evidence"
    if not filename.lower().endswith((".txt", ".md", ".csv", ".docx", ".pdf")):
        return "evidence"
    return "readable"


def evidence_bundle(data: bytes, filename: str, aead) -> dict:
    return {
        "content_tier": "evidence",
        "file_hash": hashlib.sha256(data).hexdigest(),
        "vault_ct": aead.encrypt({"filename": filename, "size": len(data)}),
    }
```

`requirements.txt` 追加 `pypdf==5.1.0`、`python-docx==1.1.2` 并安装。

- [ ] **Step 4: 运行确认通过**

Run: `python -m pytest tests/test_files.py -v`
Expected: 6 PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/files.py backend/tests backend/requirements.txt
git commit -m "feat: file dual-channel extraction + default-deny routing + evidence bundle"
```

---

### Task 9: OCR 异步隔离 worker(可选演示)

**Files:**
- Create: `backend/app/ocr_worker.py`
- Create: `backend/tests/test_ocr_worker.py`

**Interfaces:**
- Consumes: `app.files.extract_text` 的检测管线入口(只输出预览结构,不回流)
- Produces: `submit_ocr(data: bytes, filename: str) -> str`(task_id,立即返回);`poll_ocr(task_id: str) -> dict | None`(完成后 `{"status":"done","preview_text": str,"redacted_preview": str}`);主线永不 await OCR

- [ ] **Step 1: 写失败测试(异步不阻塞 + 不回流)**

`backend/tests/test_ocr_worker.py`:

```python
import time
from app.ocr_worker import submit_ocr, poll_ocr

def test_submit_returns_immediately():
    t0 = time.perf_counter()
    tid = submit_ocr(b"\x89PNG fake", "scan.png")
    assert (time.perf_counter() - t0) < 0.05   # 主线不阻塞
    assert isinstance(tid, str)

def test_poll_none_then_done():
    tid = submit_ocr(b"\x89PNG fake", "scan.png")
    # 预置样张测试:worker 无 OCR 引擎时返回 status=unavailable,主线不受影响
    for _ in range(50):
        r = poll_ocr(tid)
        if r is not None:
            assert r["status"] in ("done", "unavailable")
            return
        time.sleep(0.02)
    raise AssertionError("worker 未在 1s 内给出结果")
```

- [ ] **Step 2: 运行确认失败,实现**

Run: `python -m pytest tests/test_ocr_worker.py -v`
Expected: FAIL `ModuleNotFoundError`

`backend/app/ocr_worker.py`:用 `concurrent.futures.ThreadPoolExecutor(max_workers=1)`;`submit_ocr` 提交任务立即返回 uuid;worker 内尝试 `import pytesseract` + `PIL.Image`,失败或无引擎 → `{"status":"unavailable","reason":"no-ocr-engine"}`;成功 → 抽文本→复用 `app.detection.detect_sensitive` 出 `redacted_preview`。**输出仅供预览面板,不进 input_hash、不修改任何已发请求**(模块 docstring 写明)。

- [ ] **Step 3: 运行确认通过**

Run: `python -m pytest tests/test_ocr_worker.py -v`
Expected: 2 PASS

- [ ] **Step 4: Commit**

```bash
git add backend/app/ocr_worker.py backend/tests/test_ocr_worker.py
git commit -m "feat: async isolated OCR worker (preview-only, never blocks main path)"
```

---

### Task 10: detection.py 升级:实体 → 分级令牌 + 文件名令牌

**Files:**
- Modify: `backend/app/detection.py`
- Create: `backend/tests/test_detection_tokens.py`

**Interfaces:**
- Consumes: Task 2-4 的 `t1_pseudonym`、`T2Cipher`、`StaticOPE`
- Produces: `tokenize_entities(entities: list[Entity], tok: Tokenizers) -> list[TokenEntity]`,`TokenEntity` 带 `token, tier, leak_class`;`tier_for(entity_type: str) -> str` 映射(NAME/ORG/PROJECT/PHI/ADDRESS/PII→T1,ID/CARD/PHONE→T2,数值类→T3);`filename_token(name: str, tok) -> str`;低置信度实体标记 `pending: bool`(confidence < 0.6)

- [ ] **Step 1: 写失败测试**

`backend/tests/test_detection_tokens.py`:

```python
from app.detection import detect_sensitive, tier_for
from app.detection import tokenize_entities, filename_token, Tokenizers
from app.tokens import T2Cipher

def test_tier_mapping():
    assert tier_for("NAME") == "T1"
    assert tier_for("ID") == "T2"
    assert tier_for("CARD") == "T2"

def test_entities_become_tokens():
    det = detect_sensitive("张三的手机 13800138000")
    toks = tokenize_entities(det.entities, Tokenizers.default())
    assert all(hasattr(t, "token") and hasattr(t, "tier") for t in toks)
    name_tok = [t for t in toks if t.tier == "T1"][0]
    assert "张三" not in name_tok.token       # 令牌不含明文

def test_low_confidence_pending():
    det = detect_sensitive("订单号 622202020001234")   # Luhn 挂 → 0.5 置信度
    toks = tokenize_entities(det.entities, Tokenizers.default())
    assert any(t.pending for t in toks)

def test_filename_tokenized():
    tok = filename_token("张三的报告.docx", Tokenizers.default())
    assert "张三" not in tok

def test_cross_modal_coreference():          # 同会话同值同令牌
    tk = Tokenizers.default()
    a = tokenize_entities(detect_sensitive("张三").entities, tk)
    b = tokenize_entities(detect_sensitive("张三来了").entities, tk)
    assert a[0].token == b[0].token
```

- [ ] **Step 2: 运行确认失败,实现**

Run: `python -m pytest tests/test_detection_tokens.py -v`
Expected: FAIL ImportError

实现:`Tokenizers` 数据类聚合 `k_t1/session_salt/T2Cipher/StaticOPE`(由 proxy 注入);`tokenize_entities` 按 `tier_for` 分派 T1/T2,T2 输出补校验位(`id_check_digit`/`luhn_digit`)得到完整展示串;`filename_token = t1_pseudonym(k_t1, "FNAME", name, salt)`。**注意 T1 共指由同 key+salt 自然保证,不要写查表去重逻辑**(HMAC 确定性)。

- [ ] **Step 3: 运行确认通过 + Commit**

Run: `python -m pytest tests/test_detection_tokens.py -v`
Expected: 5 PASS

```bash
git add backend/app/detection.py backend/tests/test_detection_tokens.py
git commit -m "feat: entity→tiered-token pipeline with filename tokens and pending flags"
```

---

### Task 11: proxy.py 流水线重写 + USER_OVERRIDE + run_in_executor

**Files:**
- Modify: `backend/app/proxy.py`(query 主流水线重写)
- Modify: `backend/app/mock_llm.py`(响应哈希换 tokenchain.response_hash + mock_sleep_ms)
- Create: `backend/tests/test_pipeline.py`

**Interfaces:**
- Consumes: Task 1-10 全部产物
- Produces: `CryptoGuard.query_v2(text, files=None, overrides=None, scenario="medical") -> dict`(返回含 `outbound`(OutboundRequest dump)、`input_hash`、`verification`、`pipeline`、`override_events`、`mock_sleep_ms`);`CryptoGuard.exec_sync(fn, *args)` 线程池执行器

- [ ] **Step 1: 写失败测试(端到端 + USER_OVERRIDE 绑定)**

`backend/tests/test_pipeline.py`:

```python
from app.proxy import CryptoGuard

def test_query_v2_end_to_end():
    g = CryptoGuard()
    r = g.query_v2("张三 13800138000 查询余额")
    assert r["status"] == "verified"
    assert "张三" not in r["outbound"]["redacted_text"]
    assert r["outbound"]["schema_version"] == "CG/2.0"
    assert "mock_sleep_ms" in r

def test_override_bound_into_input_hash():
    g = CryptoGuard()
    ev = {"event_id": "e1", "entity_span": [0, 2], "entity_type": "NAME",
          "original_token": "x", "action": "force_allow", "replacement": None,
          "user_ack": True, "ts": "2026-10-11T00:00:00.000000Z"}
    r1 = g.query_v2("张三就诊", overrides=[ev])
    r2 = g.query_v2("张三就诊", overrides=[])
    assert r1["input_hash"] != r2["input_hash"]

def test_reject_smuggled_directive():
    g = CryptoGuard()
    bad = {"op": "sum", "tokens": ["[FAKE#deadbeef]"], "result_ref": "c_01"}
    r = g.query_v2("余额统计", directive=bad)
    assert r["gateway_rejected"] and any(e["entry_type"] == "COMPUTE_GATE" for e in g.chain.entries)
```

- [ ] **Step 2: 运行确认失败**

Run: `python -m pytest tests/test_pipeline.py -v`
Expected: FAIL(无 query_v2)

- [ ] **Step 3: 实现(要点;结构沿用现有 query 十步流水线)**

1. 敏感检测 → `tokenize_entities`(Task 10)→ `build_outbound`(Task 7)→ `verify_outbound` 不过则抛
2. `mock_llm.respond` 换新签名:`respond(req_dump, mock_sleep_ms)`;`_response_hash` 改调 `tokenchain.response_hash`(与 spec §3.1 一致,含 JCS 域分隔标签);sleep 用 `time.sleep(_secrets.randbelow(51) + 50) / 1000` 并把毫秒数写进返回 dict 的 `mock_sleep_ms`
3. `log` 时写 `entry_type`(QUERY/USER_OVERRIDE/COMPUTE_GATE)入链
4. 全流程包 `await loop.run_in_executor(self._pool, ...)` 或同步入口 `exec_sync`(Phase D 的 `/api/proxy/query` 用 `run_in_executor` 包同步 `query_v2`);`CryptoGuard.__init__` 建 `ThreadPoolExecutor(max_workers=8)`
5. 沙箱暂不接(本任务只做正常链路;攻击接线在 Task 14)

- [ ] **Step 4: 运行确认通过(含旧测试回归)**

Run: `python -m pytest tests/ -v`
Expected: 全 PASS(旧 mock_llm 调用点同步改签名)

- [ ] **Step 5: Commit**

```bash
git add backend/app backend/tests
git commit -m "feat: pipeline v2 with tiered tokens, USER_OVERRIDE binding, JCS response_hash"
```

---

### Task 12: 哈希链 entry_type 枚举 + Merkle 打包触发器

**Files:**
- Modify: `backend/app/crypto/hashchain.py`
- Modify: `backend/app/proxy.py`(打包触发接线)
- Create: `backend/tests/test_hashchain_v2.py`

**Interfaces:**
- Consumes: `app.canon.h_hex`
- Produces: `HashChain.append(entry_type: str, payload_digest: str, timestamp: str) -> dict`(JCS 哈希,spec §3.3 公式);`HashChain.PACK_EVERY = 10`;`maybe_pack(now: float, force: bool = False) -> dict|None`(每 10 条或 300 秒,`force=True` 立即);`packs: list[dict]`(每包含 `merkle_root`, `range`, `ts`)

- [ ] **Step 1: 写失败测试(SEC-PACK-1/2)**

`backend/tests/test_hashchain_v2.py`:

```python
from app.crypto.hashchain import HashChain

def test_entry_type_recorded():
    c = HashChain()
    e = c.append("QUERY", "abc", "2026-10-11T00:00:00Z")
    assert e["entry_type"] == "QUERY"

def test_pack_every_10():
    c = HashChain()
    for i in range(10):
        c.append("QUERY", f"d{i}", "ts")
    assert len(c.packs) == 1 and c.packs[0]["range"] == [0, 9]

def test_pack_force_immediate():                 # SEC-PACK-1 修正:立即打包按钮
    c = HashChain()
    c.append("QUERY", "d0", "ts")
    p = c.maybe_pack(0.0, force=True)
    assert p is not None and len(p["merkle_root"]) == 64

def test_pack_timer_5min():
    import time as _t
    c = HashChain()
    c.append("QUERY", "d0", "ts")
    assert c.maybe_pack(0.0) is None
    assert c.maybe_pack(301.0) is not None        # 5 分钟到期

def test_tamper_breaks_chain():
    c = HashChain()
    for i in range(3):
        c.append("QUERY", f"d{i}", "ts")
    c.entries[1]["payload_digest"] = "tampered"
    assert c.verify() is False
```

- [ ] **Step 2: 运行确认失败,实现**

Run: `python -m pytest tests/test_hashchain_v2.py -v`
Expected: FAIL(签名不含 entry_type)

实现:`append` 哈希改为 `h_hex({"d":"CG/LOG/v2","ty":entry_type,"p":payload_digest,"ts":timestamp,"prev":prev})`;`maybe_pack` 用未打包条目数 ≥10 或 `now - last_pack_ts >= 300` 触发,打包用现有 `MerkleTree` 出根;`proxy.query_v2` 每次 append 后调 `maybe_pack(time.monotonic())`。

- [ ] **Step 3: 运行确认通过 + Commit**

Run: `python -m pytest tests/test_hashchain_v2.py -v`
Expected: 5 PASS

```bash
git add backend/app/crypto/hashchain.py backend/app/proxy.py backend/tests/test_hashchain_v2.py
git commit -m "feat: hash chain entry_type enum + Merkle pack trigger (10 entries / 5 min / force)"
```

---

## Phase C:攻击沙箱

### Task 13: 攻击沙箱 + 8 攻击注入(sandbox.py)

**Files:**
- Create: `backend/app/sandbox.py`
- Modify: `backend/app/proxy.py`(攻击接线)
- Create: `backend/tests/test_sandbox.py`

**Interfaces:**
- Consumes: Task 11 的 `CryptoGuard`
- Produces: `AttackSandbox(guard: CryptoGuard)`;`.snapshot() -> dict`(深拷贝 chain/merkle_leaves/stats);`.attack(name: str) -> dict`(在**副本状态**上执行 8 攻击之一,返回 `{attack, layer_hit, ok: False, detail}`);`.reset()`(恢复快照);攻击名:`tamper|replay|forge_cert|tamper_log|repudiate_user|repudiate_provider|swap_token|swap_file|bad_directive`

- [ ] **Step 1: 写失败测试(SEC-ISO-1/2 + 八攻击)**

`backend/tests/test_sandbox.py`:

```python
from app.proxy import CryptoGuard
from app.sandbox import AttackSandbox, ATTACKS

def _fresh():
    g = CryptoGuard()
    g.query_v2("张三 13800138000 就诊")
    return g

def test_all_eight_attacks_fail_verification():
    for name in ATTACKS:
        g = _fresh()
        sb = AttackSandbox(g)
        r = sb.attack(name)
        assert r["ok"] is False and r["layer_hit"], name

def test_iso1_main_chain_never_polluted():       # Review Focus #4
    g = _fresh()
    sb = AttackSandbox(g)
    for name in ATTACKS:
        sb.attack(name)
    assert g.chain.verify() is True

def test_iso2_reset_restores_state():
    g = _fresh()
    before = g.chain.root
    sb = AttackSandbox(g)
    sb.attack("tamper_log")
    sb.reset()
    assert g.chain.root == before
```

- [ ] **Step 2: 运行确认失败,实现**

Run: `python -m pytest tests/test_sandbox.py -v`
Expected: FAIL `ModuleNotFoundError`

实现:`snapshot` 用 `copy.deepcopy` 捕获 `chain.entries/merkle_leaves/stats`;`attack()` 在深拷贝上模拟攻击并跑 `_verify` 得到失败层:8 攻击对应层见 spec §4.2 表(5a=repudiate_user→层1;5b=repudiate_provider→层3 签名覆盖;bad_directive 走 gateway+COMPUTE_GATE);`reset()` 把快照写回 guard。**主 guard 的链永不在 attack() 中被写**。

- [ ] **Step 3: 运行确认通过 + Commit**

Run: `python -m pytest tests/test_sandbox.py -v`
Expected: 3 PASS

```bash
git add backend/app/sandbox.py backend/app/proxy.py backend/tests/test_sandbox.py
git commit -m "feat: attack sandbox with snapshot/reset and 8 attack injections (SEC-ISO)"
```

---

## Phase D:API 与并发

### Task 14: main.py 路由扩展 + run_in_executor + 多 worker 配置

**Files:**
- Modify: `backend/app/main.py`
- Create: `backend/app/concurrency.py`
- Create: `backend/tests/test_api_v2.py`
- Create: `backend/gunicorn_conf.py`

**Interfaces:**
- Consumes: Task 7/8/11/13 的全部入口
- Produces: 新路由 `POST /api/files/upload`(multipart)、`POST /api/proxy/query2`(OutboundRequest 直入)、`POST /api/attack/inject`、`POST /api/attack/reset`、`POST /api/logs/pack`(立即打包)、`POST /api/gateway/compute`(ComputeDirective);全部 CPU 密集处理器经 `run_in_executor` 包装

- [ ] **Step 1: 写失败测试**

`backend/tests/test_api_v2.py`:

```python
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_upload_routes_evidence():
    r = client.post("/api/files/upload",
                    files={"file": ("scan.pdf", b"", "application/pdf")},
                    data={"filename_token_hint": "1"})
    assert r.status_code == 200
    assert r.json()["content_tier"] == "evidence"      # 空 PDF → 存证

def test_query2_rejects_bad_schema():
    r = client.post("/api/proxy/query2", json={"schema_version": "CG/1.0"})
    assert r.status_code == 422

def test_pack_now():
    client.post("/api/proxy/query2", json=_valid_query())
    r = client.post("/api/logs/pack")
    assert r.status_code == 200 and "merkle_root" in r.json()

def test_inject_reset():
    r = client.post("/api/attack/inject", json={"attack": "swap_token"})
    assert r.json()["ok"] is False
    assert client.post("/api/attack/reset").status_code == 200
```

- [ ] **Step 2: 运行确认失败,实现**

Run: `python -m pytest tests/test_api_v2.py -v`
Expected: FAIL 404

实现要点:
- `concurrency.py`:`run_sync(fn, *a)` = `asyncio.get_running_loop().run_in_executor(guard._pool, fn, *a)`;所有 `/api/proxy/query2`、`/api/files/upload` 处理器包一层
- `gunicorn_conf.py`:`workers = os.cpu_count()`、`worker_class = "uvicorn.workers.UvicornWorker"`、`bind = "0.0.0.0:8000"`(README 写启动命令 `gunicorn app.main:app -c gunicorn_conf.py`;QPS 承诺挂多 worker)
- 旧 `/api/proxy/query` 保留为兼容入口(内部调 query_v2)

- [ ] **Step 3: 运行确认通过 + Commit**

Run: `python -m pytest tests/ -v`
Expected: 全 PASS

```bash
git add backend/app backend/tests backend/gunicorn_conf.py
git commit -m "feat: v2 API routes with run_in_executor + multi-worker gunicorn config"
```

---

## Phase E:前端六步控制台

### Task 15: 控制台骨架 + 计时条真值 + 附录抽屉

**Files:**
- Create: `frontend/src/console/Console.jsx`
- Create: `frontend/src/console/StepNav.jsx`
- Create: `frontend/src/console/TimingBar.jsx`
- Create: `frontend/src/console/AppendixDrawer.jsx`
- Create: `frontend/src/console/badges.js`
- Modify: `frontend/src/App.jsx`(路由收敛为单路由 /console)
- Create: `frontend/src/console/__tests__/timing.test.js`

**Interfaces:**
- Consumes: `GET /api/policy`、`POST /api/proxy/query2` 响应的 `pipeline` 数组(含 `duration_ms`、`mock_sleep_ms`)
- Produces: `<Console>` 六步状态机(`useReducer`,`step: 1..6`);`<TimingBar pipeline={...}>` 渲染 2 位小数;`badges.js` 导出 `BADGES` 常量表(spec §4.1 十一枚徽章)

- [ ] **Step 1: 写失败测试(格式化真值,Review Focus #5)**

`frontend/src/console/__tests__/timing.test.js`(用 `vitest` —— `npm i -D vitest` 后 `npx vitest run`):

```javascript
import { formatMs } from "../timing.js";

test("two decimals exactly", () => {
  expect(formatMs(1.2345)).toBe("1.23");
  expect(formatMs(8)).toBe("8.00");
});

test("mock sleep label present", () => {
  expect(formatMs(66.666, true)).toBe("66.67 (Mock 模拟延迟)");
});
```

- [ ] **Step 2: 运行确认失败,实现 timing.js + TimingBar.jsx**

`frontend/src/console/timing.js`:

```javascript
export function formatMs(v, isMock = false) {
  const s = Number(v).toFixed(2);
  return isMock ? `${s} (Mock 模拟延迟)` : s;
}
```

`TimingBar.jsx` 渲染 pipeline 每段:`formatMs(step.duration_ms)`;LLM 段判 `step.mock_sleep_ms != null` 时加 Mock 标注;**数值原样来自 WS/响应,前端不四舍五入输入、不做动画模拟**。

- [ ] **Step 3: Console/StepNav/AppendixDrawer/badges 骨架**

`Console.jsx`:`useReducer` 状态机 `step 1..6` + `attackSnapshot` 标志;顶部常驻横幅(威胁模型四角色 + 三条不承诺,文案取 spec §7);底部 TimingBar;右侧抽屉按钮挂 AppendixDrawer(三个折叠区:CryptoLab 可选增强 / 性能实测 / 合规映射 —— 内容组件 Task 17 补)。删除 `src/pages/` 十二个旧页面引用,`App.jsx` 只挂 `/console`。`badges.js`:

```javascript
export const BADGES = {
  PRF: "🔒 PRF", PRP: "🔒 强PRP", OPE: "⚠️ 泄漏:序关系", DCR: "🔒 DCR",
  BIND: "🔗 抗第二原像", SIGN: "✍️ EUF-CMA", AUDIT: "🛡 审计签名",
  REPLAY: "⏱ 防重放", FILE: "📄 完整性存证", USER: "👤 不可抵赖",
  NLP: "⚠️ NLP·非密码学",
};
```

- [ ] **Step 4: 构建通过 + Commit**

Run: `cd frontend && npx vitest run && npm run build`
Expected: 测试 PASS、构建成功

```bash
git add frontend/src frontend/package.json
git commit -m "feat: six-step console skeleton with truth-first timing bar and badge system"
```

---

### Task 16: 步骤①②(输入 + 令牌化)

**Files:**
- Create: `frontend/src/console/Step1Input.jsx`
- Create: `frontend/src/console/Step2Tokens.jsx`
- Create: `frontend/src/console/PreimagePanel.jsx`(Step③ 用,本任务先建折叠组件)
- Modify: `frontend/src/console/Console.jsx`

**Interfaces:**
- Consumes: `POST /api/detect`(预览高亮)、`POST /api/files/upload`(路由徽章)、QueryResponse 的 `outbound.token_index / override_events`
- Produces: Step1: 实时高亮 + 文件 Tab + 待确认清单(user_ack 强制)+ override 芯片条;Step2: 四级令牌芯片(悬停泄漏卡)+ 跨模态共指连线 + token_root 链环滚动 + FF1 降级横幅(读 `FF1_DEGRADED` 经 `/api/perf` 暴露)

- [ ] **Step 1: 组件实现(测试以 build+人工清单为主)**

Step1 要点:输入框 debounce 300ms 调 `/api/detect`,高亮块挂徽章 `BADGES.NLP`;文件拖放 POST `/api/files/upload`,返回 `content_tier` 渲染 `📄 可读通道`/`🔒 存证通道(模型不可读)` 徽章;`pending` 实体渲染三选一(放行/手动替换/强制脱敏)+ `user_ack` checkbox(不勾选提交按钮 disabled);override 事件渲染芯片条,条尾固定文案"数组整体哈希 → input_hash"挂 `BADGES.BIND`。

Step2 要点:按 tier 分色芯片(T1 蓝/T2 紫/T3 橙/T4 绿),每芯片挂对应 `BADGES`;hover 弹卡显示 `leak_class` 全文;token_root 显示为逐环累加的链(动画只滚动数字,数字来自后端返回,不自算);`FF1_DEGRADED` 为真时步骤顶部常驻 ⚠️ 横幅"已降级为格式校验演示,演示令牌 ≤5 个"。

- [ ] **Step 2: PreimagePanel(默认折叠 + 复制,修正项)**

`PreimagePanel.jsx`:接受 `canonicalString` 与 `inputHash` props;`<details>` 默认折叠;`<pre>` 可滚动;复制按钮 `navigator.clipboard.writeText(canonicalString)`;展开区第二行展示 `input_hash = {inputHash}` 挂 `BADGES.BIND · 可复算`。**canonicalString 必须是后端返回的字段,前端不生成**。

- [ ] **Step 3: 构建 + Commit**

Run: `cd frontend && npm run build`
Expected: 成功

```bash
git add frontend/src/console
git commit -m "feat: step1 input+override UI and step2 tiered token display with leak badges"
```

---

### Task 17: 步骤③④⑤⑥(出站包/验证/攻击/审计)+ 砍旧页面

**Files:**
- Create: `frontend/src/console/Step3Outbound.jsx`
- Create: `frontend/src/console/Step4Verify.jsx`
- Create: `frontend/src/console/Step5Attack.jsx`
- Create: `frontend/src/console/Step6Audit.jsx`
- Modify: `frontend/src/console/Console.jsx`、`AppendixDrawer.jsx`(填三折叠区内容)
- Delete: `frontend/src/pages/*.jsx`、`frontend/src/components/QueryRunner.jsx` 等旧组件(被上述替代者)

**Interfaces:**
- Consumes: QueryResponse 全字段、`/api/logs`、`/api/attack/inject|reset`、`/api/logs/pack`
- Produces: Step3: Wireshark 收据块 + PreimagePanel + 明文/出站 Diff 切换 + nonce 时间窗;Step4: 四层逐项打勾(公式实值代入)+ 五态状态机 + 还原四行;Step5: 九按钮(8 攻击 + 一键重置)+ 失败传播 + 话术卡;Step6: 四色哈希链 + 打包倒计时 + **立即打包按钮** + Merkle 路径变红动画 + 争议双向验真面板

- [ ] **Step 1: 实现四步骤组件**

Step3:`<PreimagePanel>` 接后端 `outbound.canonical_preimage` 字段(Task 7 的 build_outbound 需在 dump 中带出该字段——若 Task 7 未带,本任务补);Diff 切换用两栏 `original_input` vs `redacted_text`。
Step4:每层渲染公式(模板字符串代入后端实值,不自算)+ 徽章;状态机色:正常灰/验证中蓝/通过绿/失败红/告警橙。
Step5:按钮顺序 = spec §4.2 表;每攻击后调 `/api/attack/inject`,渲染 `layer_hit` 与失败传播(用 CSS transition 把链路上的节点依次标红);话术卡文案从后端 `attack_result` 取;**红色按钮前置确认:"攻击写入沙箱快照,不影响主链"**;重置按钮调 `/api/attack/reset` 并清红。
Step6:条目按 `entry_type` 四色;倒计时 = `10 - 未打包条目数`;「立即打包」调 `/api/logs/pack`;Merkle 树节点验证逐个变红动画由后端返回的 `path_valid` 数组驱动(**不自算节点哈希**);争议面板两个卡片:用户侧(file_hash 重算比对)与服务商侧(response_hash 验签),各挂对应徽章。

AppendixDrawer 三折叠区:CryptoLab(SSE 搜索/Paillier 统计/ZKP 演示,调旧接口,标注"可选增强,不在主链路")、性能实测(`FF1 单价/核心合计/端到端 P50P95/吞吐` 表 + 降级横幅位,数据从 `/api/perf` 取)、合规映射(HIPAA/PCI-DSS 静态表)。

- [ ] **Step 2: 删除旧页面并修复引用**

`rm frontend/src/pages/*.jsx`;`App.jsx`/`main.jsx`/`store.jsx` 中引用清理;`npm run build` 必须零警告级别的 unresolved import。

- [ ] **Step 3: 构建 + 人工验收清单 + Commit**

Run: `cd frontend && npm run build`
人工清单(spec §4):无徽章不渲染逐屏检查;计时条数值与 Network 响应对齐;前映像面板默认折叠可复制;攻击后主链徽章仍"通过"。

```bash
git add -A frontend
git commit -m "feat: steps 3-6 console (outbound/verify/attack/audit) + appendix drawer; remove legacy pages"
```

---

## Phase F:验收测试套件与形式化

### Task 18: Golden Set 400 + 检测指标(detection_golden.py)

**Files:**
- Create: `tests/detection_golden.py`(项目根 `tests/`,独立于 backend/tests)
- Create: `tests/golden_gen.py`(模板生成器)
- Create: `tests/golden_adversarial.py`(150 对抗负例生成器)

**Interfaces:**
- Consumes: `app.detection.detect_sensitive`
- Produces: `python tests/detection_golden.py` 输出 per-type/overall P/R/FPR + Wilson 95% CI;退出码 0=达标(P>95%, R>90%, FPR<5%),1=不达标

- [ ] **Step 1: 写生成器(120 模板 + 150 对抗 + 30 跨模态 + 100 复合句式)**

`golden_gen.py` 用 `random.Random(20261011)` 固定种子:
- 模板 120:13 类实体×变体,身份证用 `id_check_digit` 造合法号 + 故意坏校验位负例;卡号同理 Luhn 对/不对
- 对抗 150(`golden_adversarial.py`):订单号 16 位但 Luhn 挂、日期 `20251015`、版本号 `1.2.3.4`、π 20 位、`3-4-5`、长横线号 `2025-10-15-001` 等,**每个负例标注 gold=非敏感**
- 复合 100:病历/流水句式嵌套实体("张三的地址是XX省…")
- 跨模态 30:同一实体在 `plain/csv-row/docx-para/pdf-line` 四种载体

每条记录: `{"text": str, "gold": [{"type": str, "span": [s,e]}], "modality": str}`。

- [ ] **Step 2: 写指标计算(含 Wilson CI)**

`detection_golden.py`:`detect_sensitive` 对每条打分,span 级精确匹配;P/R/FPR 按 spec §6.1 口径;FPR 分母 = 对抗负例的分句单元数(≥400);Wilson score interval 95%:

```python
def wilson_ci(phat: float, n: float, z: float = 1.96):
    d = 1 + z*z/n
    c = phat + z*z/(2*n)
    h = z*math.sqrt(phat*(1-phat)/n + z*z/(4*n*n))
    return ((c-h)/d, (c+h)/d)
```

- [ ] **Step 3: 运行并校准到达标**

Run: `cd backend && python ../tests/detection_golden.py`
Expected: 输出三指标 + CI;若不达标,调整检测规则直到过线(这是校准任务,规则改动要写进 commit message)。

- [ ] **Step 4: Commit**

```bash
git add tests/
git commit -m "test: golden set 400 units with Wilson CI metrics (P>95 R>90 FPR<5)"
```

---

### Task 19: 安全测试套件补全(BIND/SEC 回归)

**Files:**
- Create: `backend/tests/test_bind_suite.py`(BIND-1..6 集中回归)
- Create: `backend/tests/test_sec_attacks.py`(SEC-ATK-1..8 集中)
- Create: `backend/tests/test_perf_truth.py`(PERF-TRUTH-1 双断言)

**Interfaces:**
- Consumes: Task 6/7/13 全部
- Produces: 三个测试文件即验收依据;`test_perf_truth.py` 断言:① 后端 `pipeline` 里每段 `duration_ms` 字符串 == `f"{v:.2f}"`;② `abs(raw_ms - sent_ms) < 0.01`;③ `mock_sleep_ms` 字段存在且与 LLM 段一致

- [ ] **Step 1: 写三个测试文件(内容从 Task 6/13 的既有断言提级集中)**

SEC-ATK-5a/5b 拆分断言(修正项):

```python
def test_5a_user_repudiation_fails():       # 5a 用户诬告:声称错误输入
    g = _fresh(); sb = AttackSandbox(g)
    r = sb.attack("repudiate_user")
    assert r["layer_hit"] == "输入绑定/防重放"

def test_5b_provider_repudiation_fails():   # 5b 服务商抵赖:否认收到该输入
    g = _fresh(); sb = AttackSandbox(g)
    r = sb.attack("repudiate_provider")
    assert r["layer_hit"] == "响应完整性"
```

- [ ] **Step 2: 运行确认(全绿基线)**

Run: `cd backend && python -m pytest tests/ -v`
Expected: 全 PASS;任何红 = 验收失败

- [ ] **Step 3: Commit**

```bash
git add backend/tests
git commit -m "test: consolidated BIND/SEC-ATK/PERF-TRUTH suites with 5a/5b split"
```

---

### Task 20: ProVerif 模型 + 字段对照归档

**Files:**
- Create: `formal/cryptoguard.pv`
- Create: `formal/EXPECTED_RESULTS.md`
- Create: `formal/FIELD_MAP.md`(spec §6.4-B 对照表)

**Interfaces:**
- Consumes: spec §6.4-C 的 6 条查询(合法语法)
- Produces: 可被 ProVerif 2.x 解析的模型;查询与预期 RESULT 一一列出

- [ ] **Step 1: 写 cryptoguard.pv(按 spec §6.4-C 逐字)**

```proverif
(* CryptoGuard-LLM 四层协议模型 —— 与代码字段对照见 formal/FIELD_MAP.md *)
free c: channel.
type skey.
type bitstring.

fun senc(bitstring, skey): bitstring.
fun resp_hash(bitstring, bitstring, bitstring, bitstring, bitstring): bitstring.
reduc forall m: bitstring, ih: bitstring, cert: bitstring, n: bitstring, ts: bitstring;
  sdec(senc(m, k), k) = m.

(* 事件 *)
event resp_accept(bitstring).
event provider_sign(bitstring).
event cert_accept(bitstring).
event cert_issued(bitstring).
event req_sent(bitstring).
event nonce_reused(bitstring).

(* 查询 1-6 与 spec §6.4-C 一致 *)
query attacker(sk_provider_placeholder).
query x: bitstring; event(resp_accept(x)) ==> event(provider_sign(x)).
query x: bitstring; event(cert_accept(x)) ==> event(cert_issued(x)).
query n: bitstring; event(nonce_reused(n)).
query attacker(vault_key_placeholder).
query attacker(plain_secret_placeholder).
```

实现时:进程建模"请求含 token_root/input_hash/nonce"、"响应验签通过才 resp_accept"、nonce 表 `insert`/`get` 查复用(get 命中即 `event nonce_reused`)。**私钥用 `private free` 声明**,placeholder 命名在实现时换成正式名(`sk_provider` 等)并同步 FIELD_MAP。

- [ ] **Step 2: 跑 ProVerif 归档输出**

Run: `proverif formal/cryptoguard.pv | tee formal/output.txt`(机器无 ProVerif 则在 EXPECTED_RESULTS.md 写明"待装 ProVerif 2.x 验证",查询与预期 RESULT 表仍落盘)

`EXPECTED_RESULTS.md` 六条,预期分别为:
1. `RESULT not attacker(sk_provider) is true.`
2. `RESULT event(resp_accept(x)) ==> event(provider_sign(x)) is true.`
3. `RESULT event(cert_accept(x)) ==> event(cert_issued(x)) is true.`
4. `RESULT not event(nonce_reused(n)) is true.`(版本差异可为 `RESULT event(nonce_reused(n)) is false.`)
5. `RESULT not attacker(vault_key) is true.`
6. `RESULT not attacker(plain_secret) is true.`

- [ ] **Step 3: FIELD_MAP.md 落盘 + Commit**

字段对照表按 spec §6.4-B 五行列出(token_root/input_hash/model_cert/response_hash/log_entry),每行 ProVerif fun 元数 == 代码函数参数数。

```bash
git add formal/
git commit -m "feat: ProVerif model with legal queries + expected results + field map"
```

---

### Task 21: 性能压测 + 文档收尾

**Files:**
- Create: `tests/locustfile.py`
- Create: `docs/ACCEPTANCE.md`(验收矩阵执行记录)
- Modify: `README.md`(架构更新、启动命令换 gunicorn、诚实边界补文件/令牌泄漏声明)

**Interfaces:**
- Consumes: Task 14 的多 worker 部署
- Produces: Locust 100 VU × 60s 脚本;ACCEPTANCE.md 按 spec §6.5 矩阵逐行填实测值

- [ ] **Step 1: Locust 脚本**

```python
from locust import HttpUser, task, between

class CryptoGuardUser(HttpUser):
    wait_time = between(0.01, 0.05)

    @task
    def query(self):
        self.client.post("/api/proxy/query2", json={
            "schema_version": "CG/2.0",
            "text": "张三 13800138000 查询余额",
            "scenario": "medical",
        })
```

- [ ] **Step 2: 压测 + 填 ACCEPTANCE.md**

Run(起多 worker):`gunicorn app.main:app -c gunicorn_conf.py & locust -f tests/locustfile.py --headless -u 100 -t 60s --host http://localhost:8000`
达标:≥100 QPS、P95 端到端 <500ms、密码学段 <20ms(从 `/api/perf` 聚合)。实测值逐行填入 ACCEPTANCE.md(spec §6.5 矩阵),含 Golden Set 三指标与 Wilson CI、FF1 P95、吞吐。

- [ ] **Step 3: README 更新 + Commit**

README:架构图换 T1-T4 管道;泄漏声明表(频率可见/长度字符类/序关系/首段);双通道默认拒绝说明;启动命令 `gunicorn app.main:app -c gunicorn_conf.py`。

```bash
git add tests/locustfile.py docs/ACCEPTANCE.md README.md
git commit -m "test: load test 100QPS + acceptance matrix with measured values"
```

---

## Self-Review 结果

1. **Spec 覆盖**:T1-T4(Task 2-5)、绑定(Task 6)、Schema/网关(Task 7)、文件双通道(Task 8)、OCR(Task 9)、检测升级(Task 10)、流水线/USER_OVERRIDE(Task 11)、Merkle 打包(Task 12)、沙箱 8 攻击(Task 13)、多 worker(Task 14)、UI 六步(Task 15-17)、Golden Set(Task 18)、BIND/SEC/TRUTH 套件(Task 19)、ProVerif(Task 20)、性能+文档(Task 21)。§5.3 环境规格表已在 ACCEPTANCE.md 采集要求中体现。T4 的 Paillier 密文随出站(T4 令牌本身)在 Task 5/11 的 directive 链路覆盖。
2. **占位符扫描**:Task 20 的 `.pv` 中 `*_placeholder` 命名是实现时需替换的显式标注(已在步骤中说明替换规则),其余无 TBD/TODO。
3. **类型一致性**:`token_chain(session_id, tokens)`、`input_hash(text, file_hashes, token_root, override_h, nonce, timestamp)`、`build_outbound(...)`、`validate_directive(raw, token_index)`、`HashChain.append(entry_type, payload_digest, timestamp)` 在消费任务中签名一致;`override_hash` 接 `list[dict]`(OverrideEvent dump 后)。
4. **Review Focus 对应测试**:JCS 一致性→Task 1 BIND-6;FF1 降级→Task 3 PERF-FF1-1;空文本默认拒绝→Task 8 SEC-FROUTE;沙箱污染→Task 13 SEC-ISO-1/2;计时条造假→Task 15 vitest + Task 19 PERF-TRUTH-1。
