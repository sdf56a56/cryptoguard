"""
BIND-1..6 协议绑定属性集中回归(spec §6.2-A)—— 断言到具体公式。

BIND-1 换 token_index 任一令牌 -> input_hash 重算失配,网关拒
BIND-2 JCS 稳定性:同数据不同键序/空白 -> 规范化字节串逐字节相等
BIND-3 改文件 redacted_content 一字节 -> file_content_hash 失配拒绝
BIND-4 声称无放行但链上有 force_allow -> override_hash 与 input_hash 不符,诬告证伪
BIND-5 空数组/全空格/Unicode NFC-NFD -> 无异常、哈希稳定
BIND-6 JCS RFC 8785 符合性测试向量 + rfc8785/canonicaljson 双库交叉验证
"""
import json

from app.canon import canon, h_hex
from app.schemas import FilePayload, TokenRef, build_outbound, verify_outbound
from app.tokenchain import (file_content_hash, input_hash, override_hash,
                            token_chain)

K_T1, SALT = b"k" * 32, b"s" * 16
TOK_A = "aaaaabbbbbcccccddddd222222"      # 26 位小写 base32 T1 全量令牌
TOK_B = "zzzzzyyyyyxxxxxwwwwwvvvvvv"      # 另一枚令牌(换掉后 token_root 变)


def _idx(tok=TOK_A, typ="NAME"):
    return [TokenRef(token=tok, type=typ, tier="T1", leak_class="等值性")]


def _outbound(**over):
    base = dict(
        session_id="a" * 32,
        redacted_text=f"患者 [NAME#{TOK_A[:10]}] 就诊",
        file_payloads=[],
        token_index=_idx(),
        override_events=[],
        nonce="b" * 32,
        timestamp="2026-10-11T00:00:00.000000Z",
    )
    base.update(over)
    return build_outbound(**base)


# ------------------------------------------------------------------ BIND-1
def test_bind1_swap_token_index_breaks_input_hash():
    """换 token_index 任一令牌 -> token_root 变 -> input_hash 重算失配,网关拒。"""
    req = _outbound()
    assert verify_outbound(req, K_T1, SALT) == []

    swapped = req.model_copy(deep=True)
    swapped.token_index = _idx(tok=TOK_B)
    violations = verify_outbound(swapped, K_T1, SALT)
    assert any("input_hash 重算不一致" in v for v in violations)

    # 偷换正文里的令牌(张冠李戴):不在 token_index 白名单 -> 规则 1 拒
    swapped2 = req.model_copy(deep=True)
    swapped2.redacted_text = f"患者 [NAME#{TOK_B[:10]}] 就诊"
    violations2 = verify_outbound(swapped2, K_T1, SALT)
    assert any("不在 token_index" in v for v in violations2)

    # token_root 链式公式:换令牌 -> 链根必变(顺序累加链)
    root_a = token_chain("a" * 32, [("NAME", TOK_A)])
    root_b = token_chain("a" * 32, [("NAME", TOK_B)])
    assert root_a != root_b


# ------------------------------------------------------------------ BIND-2
def test_bind2_jcs_key_order_and_whitespace_stability():
    """同数据不同键序/空白 -> 规范化字节串逐字节相等。"""
    a = {"b": "2", "a": "1", "c": {"z": 1, "y": [3, 2]}, "d": "中文"}
    b = {"d": "中文", "c": {"y": [3, 2], "z": 1}, "a": "1", "b": "2"}
    assert canon(a) == canon(b)

    # 不同空白的 JSON 文本解析出同数据 -> 同前映像
    j1 = json.loads('{"a": "1", "b": "2"}')
    j2 = json.loads('{\n  "a"  :  "1",\n\t"b":"2"\n}')
    assert canon(j1) == canon(j2)
    assert h_hex(j1) == h_hex(j2)


# ------------------------------------------------------------------ BIND-3
def test_bind3_file_content_one_byte_flip_rejected():
    """改文件 redacted_content 一字节 -> file_content_hash 失配拒绝。"""
    content = "化验单:白细胞 6.5,血小板 220"
    fp = FilePayload(
        file_ref="file_1", filename_token="fname000001", content_tier="readable",
        redacted_content=content,
        file_content_hash=file_content_hash(content),
        file_hash="c" * 64)
    req = _outbound(file_payloads=[fp],
                    redacted_text=f"患者 [NAME#{TOK_A[:10]}] 提交化验单")
    assert verify_outbound(req, K_T1, SALT) == []

    # 一字节偷换(6.5 -> 9.5),声明哈希保留旧值 -> 违规
    tampered = req.model_copy(deep=True)
    tampered.file_payloads[0].redacted_content = content.replace("6.5", "9.5")
    violations = verify_outbound(tampered, K_T1, SALT)
    assert any("file_content_hash 与内容不一致" in v for v in violations)

    # 偷换后重算的内容哈希不同(文件绑定打穿层 3 的前提)
    assert file_content_hash(content.replace("6.5", "9.5")) != \
        file_content_hash(content)


# ------------------------------------------------------------------ BIND-4
def test_bind4_false_no_allow_claim_falsified_by_override_hash():
    """声称无放行但链上有 force_allow -> override_hash 与 input_hash 不符,诬告证伪。"""
    ev = {"event_id": "e1", "entity_span": [0, 2], "entity_type": "NAME",
          "original_token": TOK_A, "action": "force_allow", "replacement": None,
          "user_ack": True, "ts": "2026-10-11T00:00:00.000000Z"}
    req = _outbound(override_events=[ev])
    assert verify_outbound(req, K_T1, SALT) == []
    # 事件确实绑进了 input_hash(公式逐项代入可复算)
    assert req.input_hash == input_hash(
        req.redacted_text, [], req.token_root,
        override_hash([ev]), req.nonce, req.timestamp)

    # 用户诬告「没有放行」:用空事件重算 -> 与被签名的 input_hash 不符
    claim_hash = input_hash(req.redacted_text, [], req.token_root,
                            override_hash([]), req.nonce, req.timestamp)
    assert claim_hash != req.input_hash

    # 网关按请求字段重算同样不符(空数组 override_hash 是确定常量)
    claimed = req.model_copy(deep=True)
    claimed.override_events = []
    assert any("input_hash 重算不一致" in v
               for v in verify_outbound(claimed, K_T1, SALT))


# ------------------------------------------------------------------ BIND-5
def test_bind5_empty_blank_nfc_nfd_stable():
    """空数组/全空格/Unicode NFC-NFD -> 无异常、哈希稳定。"""
    # 空数组:override_hash 确定(空数组同样有确定哈希)
    assert override_hash([]) == override_hash([])
    assert len(override_hash([])) == 64
    # 全空格文本:无异常、哈希稳定
    assert h_hex({"d": "CG/TEXT/v2", "x": "   "}) == \
        h_hex({"d": "CG/TEXT/v2", "x": "   "})
    # NFC / NFD 等价码点 -> 同前映像(canon NFC 预归一化策略)
    nfc = {"k": "é"}          # e-acute 预组合(U+00E9)
    nfd = {"k": "é"}         # e + 组合尖音(U+0065 U+0301)
    assert canon(nfc) == canon(nfd)
    assert h_hex(nfc) == h_hex(nfd)
    # build_outbound 空令牌索引 + 全空格正文:不抛异常、input_hash 64 位
    req = _outbound(redacted_text="   ", token_index=[])
    assert len(req.input_hash) == 64


# ------------------------------------------------------------------ BIND-6
def test_bind6_rfc8785_vectors_and_dual_lib_crosscheck():
    """RFC 8785 符合性向量(浮点/Unicode/转义)逐字节一致 + 双库交叉验证。"""
    bs = chr(92)   # 反斜杠(构造期望串,避免转义歧义)

    # 浮点(ECMAScript NumberToString):1.0->"1"、1e3->"1000"、小数原样
    assert canon({"n": 1.0}) == b'{"n":1}'
    assert canon({"n": 1e3}) == b'{"n":1000}'
    assert canon({"n": 1.5}) == b'{"n":1.5}'
    assert canon({"n": 0.1}) == b'{"n":0.1}'
    assert canon({"n": -1.25}) == b'{"n":-1.25}'
    # 键序:按 UTF-16 码元升序
    assert canon({"b": 1, "a": 2, "B": 3, "A": 4}) == \
        b'{"A":4,"B":3,"a":2,"b":1}'
    # 转义:引号/反斜杠/控制字符,正斜杠不转义
    assert canon({"k": 'a"b' + bs + 'c'}) == (
        '{"k":"a' + bs + '"b' + bs + bs + 'c"}').encode("utf-8")
    ctrl = chr(8) + chr(12) + chr(10) + chr(13) + chr(9)
    exp_ctrl = '{"k":"' + bs + 'b' + bs + 'f' + bs + 'n' + bs + 'r' + bs + 't"}'
    assert canon({"k": ctrl}) == exp_ctrl.encode("utf-8")
    assert canon({"k": chr(0)}) == ('{"k":"' + bs + 'u0000"}').encode("utf-8")
    assert canon({"k": "a/b"}) == b'{"k":"a/b"}'
    # Unicode:非 ASCII 原样 UTF-8;NFC/NFD 等价 -> 同字节(NFC 预归一化策略)
    assert canon({"k": "é"}) == '{"k":"é"}'.encode("utf-8")
    assert canon({"k": "é"}) == canon({"k": "e" + chr(0x0301)})

    # 双库交叉验证(裁定 R13:rfc8785 主选;共享子集上与 canonicaljson 同输出)
    from canonicaljson import encode_canonical_json as _cj
    from rfc8785 import dumps as _rfc_dumps
    sample = {"s": 'a"b' + bs + 'c' + chr(10)}
    for obj in ({"a": "b", "c": 1}, {"k": "中文"}, sample,
                {"z": [1, 2], "a": {"y": 1, "x": 2}}):
        assert canon(obj) == _rfc_dumps(obj)
        assert _rfc_dumps(obj) == _cj(obj), obj
