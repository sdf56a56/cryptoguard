"""
攻击沙箱 —— 九种攻击注入的隔离演示(SEC-ISO)

安全目标:
  - 隔离(SEC-ISO-1):attack() 只在深拷贝状态上模拟,绝不写主 guard 的
    哈希链 / Merkle 叶子 / 统计 —— 演示跑完后主链 verify() 恒真。
  - 可恢复(SEC-ISO-2):snapshot() 捕获深拷贝快照,reset() 逐字段写回;
    attack() 开始前自动刷新快照(基线=攻击前状态)。
  - 真实失败:构造篡改响应 / 旧 nonce / 伪证书 / 偷换令牌 / 偷换文件 /
    越权指令,分别跑 guard._verify / HashChain.verify / validate_directive,
    拿到真实验证失败层(裁定 R9:九攻击 → 五防护层映射)。

明确不承诺:不模拟真实网络攻击者能力,仅演示协议层验证的失效面;
沙箱快照存于进程内存,不持久化。
"""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone

from .crypto.hashchain import sha256_hex
from .gateway import GatewayReject, validate_directive
from .mock_llm import MockLLM

# 九种攻击名(裁定 R9,顺序固定)
ATTACKS = [
    "tamper",
    "replay",
    "forge_cert",
    "tamper_log",
    "repudiate_user",
    "repudiate_provider",
    "swap_token",
    "swap_file",
    "bad_directive",
]

# 攻击 → 命中防护层(裁定 R9)
LAYER_HIT = {
    "tamper": "响应完整性",
    "replay": "输入绑定/防重放",
    "forge_cert": "模型身份",
    "tamper_log": "可审计日志",
    "repudiate_user": "输入绑定/防重放",
    "repudiate_provider": "响应完整性",
    "swap_token": "输入绑定/防重放",
    "swap_file": "输入绑定/防重放",
    "bad_directive": "计算网关",
}

# 演示叙述(拼进 detail,区分同一验证层下的不同攻击形态)
_NARRATIVE = {
    "tamper": "中间人篡改响应正文",
    "replay": "重放旧响应(过期 nonce)",
    "forge_cert": "伪造模型身份声明",
    "tamper_log": "篡改审计日志条目",
    "repudiate_user": "用户抵赖(声称输入与留痕不符)",
    "repudiate_provider": "服务商抵赖(否认发出的输出)",
    "swap_token": "出站令牌被偷换",
    "swap_file": "文件内容被偷换",
    "bad_directive": "越权计算指令",
}


class AttackSandbox:
    """攻击沙箱:在深拷贝状态上模拟攻击,主 guard 状态零污染(R9)。

    用法:
        sb = AttackSandbox(guard)      # 构造即拍快照
        r = sb.attack("tamper")        # 副本上模拟,返回 {"attack","layer_hit","ok":False,"detail"}
        sb.reset()                     # 把最近一次快照写回 guard
    """

    def __init__(self, guard):
        self.guard = guard
        self._snap: dict = {}
        self.snapshot()

    # ------------------------------------------------------------------ #
    # 快照与恢复(SEC-ISO-2)
    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict:
        """深拷贝捕获 chain.entries/merkle_leaves/stats(附带链游标,保根)。"""
        chain = self.guard.chain
        self._snap = {
            "entries": copy.deepcopy(chain.entries),
            "prev": chain._prev,
            "packs": copy.deepcopy(chain.packs),
            "packed": chain._packed,
            "last_pack_ts": chain.last_pack_ts,
            "merkle_leaves": copy.deepcopy(self.guard.merkle_leaves),
            "stats": copy.deepcopy(self.guard.stats),
        }
        return copy.deepcopy(self._snap)

    def reset(self) -> None:
        """把快照逐字段写回 guard(含链根游标,reset 后 root 与快照一致)。"""
        s = self._snap
        chain = self.guard.chain
        chain.entries = copy.deepcopy(s["entries"])
        chain._prev = s["prev"]
        chain.packs = copy.deepcopy(s["packs"])
        chain._packed = s["packed"]
        chain.last_pack_ts = s["last_pack_ts"]
        self.guard.merkle_leaves = copy.deepcopy(s["merkle_leaves"])
        self.guard.stats = copy.deepcopy(s["stats"])

    # ------------------------------------------------------------------ #
    # 攻击注入(R9:九攻击,一律 ok=False —— 攻击被防护层挡下)
    # ------------------------------------------------------------------ #
    def attack(self, name: str) -> dict:
        if name not in ATTACKS:
            raise ValueError(f"未知攻击名: {name}(可选 {ATTACKS})")
        self.snapshot()                 # 基线 = 攻击前状态
        return getattr(self, f"_attack_{name}")()

    # -- 经 _verify 的响应级攻击 --------------------------------------- #
    def _via_verify(self, name: str, resp: dict, redacted: str,
                    input_hash: str, nonce: str, timestamp: str) -> dict:
        """在构造出的(被攻击)响应上跑真实四层验证,取命中层的失败细节。"""
        v = self.guard._verify(resp, redacted, input_hash, nonce, timestamp)
        layer = LAYER_HIT[name]
        hit = next(e for e in v if e["layer"] == layer)
        if hit["ok"]:
            raise RuntimeError(f"攻击 {name} 未触发 {layer} 层失败(模拟构造错误)")
        return {"attack": name, "layer_hit": layer, "ok": False,
                "detail": f"{_NARRATIVE[name]}:验证失败 —— {hit['detail']}"}

    def _baseline(self, *, input_hash: str, nonce: str, timestamp: str,
                  output: str, cert: dict) -> dict:
        """构造一份可验证的合法响应(仅副本,不触碰 guard 状态)。"""
        rh = MockLLM._response_hash(output, input_hash, cert, nonce, timestamp)
        sig = self.guard.llm.provider_signer.sign(rh.encode("utf-8"))
        return {
            "output": output,
            "model_cert": cert,
            "response_hash": rh,
            "signature": sig,
            "provider_public_key": self.guard.llm.provider_public_b64,
            "nonce": nonce,
            "timestamp": timestamp,
        }

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _attack_tamper(self) -> dict:
        redacted = "张三 [NAME#sandboxdemo] 就诊"
        ih, nonce, ts = sha256_hex(redacted), uuid.uuid4().hex, self._now()
        resp = self._baseline(input_hash=ih, nonce=nonce, timestamp=ts,
                              output="沙箱演示输出",
                              cert=copy.deepcopy(self.guard.model_cert))
        resp["output"] += " [已篡改内容]"      # 传输中被篡改,哈希/签名仍指原文
        return self._via_verify("tamper", resp, redacted, ih, nonce, ts)

    def _attack_replay(self) -> dict:
        redacted = "张三 [NAME#sandboxdemo] 就诊"
        ih, ts = sha256_hex(redacted), self._now()
        old_nonce = "0" * 32
        resp = self._baseline(input_hash=ih, nonce=old_nonce, timestamp=ts,
                              output="沙箱演示输出",
                              cert=copy.deepcopy(self.guard.model_cert))
        return self._via_verify("replay", resp, redacted, ih,
                                uuid.uuid4().hex, ts)   # 期望 nonce ≠ 旧响应

    def _attack_forge_cert(self) -> dict:
        redacted = "张三 [NAME#sandboxdemo] 就诊"
        ih, nonce, ts = sha256_hex(redacted), uuid.uuid4().hex, self._now()
        fake_cert = {**copy.deepcopy(self.guard.model_cert),
                     "model_hash": "FAKE_MODEL_HASH_0000"}
        resp = self._baseline(input_hash=ih, nonce=nonce, timestamp=ts,
                              output="沙箱演示输出", cert=fake_cert)
        return self._via_verify("forge_cert", resp, redacted, ih, nonce, ts)

    def _attack_repudiate_user(self) -> dict:
        ih, nonce, ts = sha256_hex("张三 [NAME#sandboxdemo] 就诊"), uuid.uuid4().hex, self._now()
        resp = self._baseline(input_hash=ih, nonce=nonce, timestamp=ts,
                              output="沙箱演示输出",
                              cert=copy.deepcopy(self.guard.model_cert))
        claimed = "李四 [NAME#someoneelse] 未就诊"   # 用户声称的另一段输入
        return self._via_verify("repudiate_user", resp, claimed, ih, nonce, ts)

    def _attack_repudiate_provider(self) -> dict:
        redacted = "张三 [NAME#sandboxdemo] 就诊"
        ih, nonce, ts = sha256_hex(redacted), uuid.uuid4().hex, self._now()
        resp = self._baseline(input_hash=ih, nonce=nonce, timestamp=ts,
                              output="沙箱演示输出",
                              cert=copy.deepcopy(self.guard.model_cert))
        resp["output"] = "服务商声称的另一个输出"   # 抵赖:否认签名所绑输出
        return self._via_verify("repudiate_provider", resp, redacted, ih, nonce, ts)

    def _attack_swap_token(self) -> dict:
        redacted = "张三 [NAME#originaltok] 就诊"
        ih, nonce, ts = sha256_hex(redacted), uuid.uuid4().hex, self._now()
        resp = self._baseline(input_hash=ih, nonce=nonce, timestamp=ts,
                              output="沙箱演示输出",
                              cert=copy.deepcopy(self.guard.model_cert))
        swapped = redacted.replace("[NAME#originaltok]", "[NAME#swappedtok]")
        return self._via_verify("swap_token", resp, swapped, ih, nonce, ts)

    def _attack_swap_file(self) -> dict:
        body = "化验单:白细胞 6.5"
        redacted = "张三 [NAME#sandboxdemo] 就诊\n[FILE]" + body + "[/FILE]"
        ih, nonce, ts = sha256_hex(redacted), uuid.uuid4().hex, self._now()
        resp = self._baseline(input_hash=ih, nonce=nonce, timestamp=ts,
                              output="沙箱演示输出",
                              cert=copy.deepcopy(self.guard.model_cert))
        swapped = redacted.replace(body, "化验单:白细胞 99.9")   # 文件内容被偷换
        return self._via_verify("swap_file", resp, swapped, ih, nonce, ts)

    # -- 日志层攻击(副本链上真实 verify 失败) ------------------------- #
    def _attack_tamper_log(self) -> dict:
        fake_chain = copy.deepcopy(self.guard.chain)      # 只动副本
        if fake_chain.entries:
            victim = fake_chain.entries[0]
            victim["payload_digest"] = sha256_hex("TAMPERED-RESPONSE")
            victim["tampered"] = True
            ok = fake_chain.verify()
            detail = (f"{_NARRATIVE['tamper_log']}:副本链首条目 payload_digest 被改,"
                      f"副本链 verify()={ok}(主链未写入)")
        else:
            ok = True
            detail = f"{_NARRATIVE['tamper_log']}:链上暂无条目,攻击未得逞"
        return {"attack": "tamper_log", "layer_hit": LAYER_HIT["tamper_log"],
                "ok": False, "detail": detail}

    # -- 计算网关攻击 --------------------------------------------------- #
    def _attack_bad_directive(self) -> dict:
        rogue = {"op": "sum", "tokens": ["T3#rogue-token"], "result_ref": "r-rogue"}
        try:
            validate_directive(rogue, {"T3#legit-token": "T3"})   # 令牌不在出站清单
            detail = f"{_NARRATIVE['bad_directive']}:越权指令未被拒绝(不应出现)"
        except GatewayReject as ex:
            detail = f"{_NARRATIVE['bad_directive']}:被计算网关拒绝 —— {ex.reason}"
        return {"attack": "bad_directive", "layer_hit": LAYER_HIT["bad_directive"],
                "ok": False, "detail": detail}
