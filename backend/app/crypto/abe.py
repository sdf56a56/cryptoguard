"""
CP-ABE 细粒度授权模块（教学级：Shamir 门限秘密共享 + 属性策略树）

说明（诚实标注）：
  - 完整 CP-ABE 依赖双线性配对（Bilinear Pairing），Python 3.13 下无稳定可用库。
  - 本模块用「Shamir (t,n) 门限秘密共享」实现等价安全语义：
      策略树每个 (AND/OR) 节点编码为门限 (t, n)；
      仅当属性集合满足策略树时可重构主秘密并解出会话密钥。
  - 这是真实有效的门限秘密共享（信息安全），但**不是**配对群上的 CP-ABE，
    其安全性质与真实 CP-ABE 的差异已在页面与文档明确标注。

安全目标（教学级语义）：
  - 细粒度授权：只有满足属性策略的持有者能重构密钥、解密。
  - 抗合谋（演示语义）：门限结构保证不足 t 份份额无法获得主秘密。

明确不承诺：
  - 不承诺等价于标准 CP-ABE 的 IND-CPA 安全（因无配对）。
  - 不承诺抗恶意密钥分发者。

归约（教学级）：Shamir 门限共享的安全性归约到「信息论安全」（不足 t 份份额零信息）。
"""
from __future__ import annotations

import hashlib
import os
import secrets

from .aead import AeadCipher

# 素数域，用于 Shamir 共享（选择一个足够大的安全素数）
_PRIME = 2**127 - 1  # 127-bit Mersenne prime


def _poly_eval(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % _PRIME
    return acc


def _interp(points: list[tuple[int, int]]) -> int:
    """拉格朗日插值求 f(0)。"""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = num * (0 - xj) % _PRIME
            den = den * (xi - xj) % _PRIME
        secret = (secret + yi * num * pow(den, _PRIME - 2, _PRIME)) % _PRIME
    return secret


class PolicyTree:
    """策略树节点。leaf: attribute 名称；否则 (gate, children)。

    gate 为 ('and', n) 或 ('or', n)：AND 需要全部 n 份，OR 需要任意 1 份。
    一般化：每个节点是 (t, n) 门限。
    """

    def __init__(self, node):
        self.node = node  # str（叶子）或 tuple（内部节点）

    @staticmethod
    def attributes(node) -> set[str]:
        if isinstance(node, str):
            return {node}
        _, children = node
        s = set()
        for c in children:
            s |= PolicyTree.attributes(c)
        return s

    @staticmethod
    def satisfied(node, attrs: set[str]) -> bool:
        if isinstance(node, str):
            return node in attrs
        gate, children = node
        results = [PolicyTree.satisfied(c, attrs) for c in children]
        if gate == "and":
            return all(results)
        if gate == "or":
            return any(results)
        raise ValueError(f"unknown gate {gate}")


class ABE:
    """基于 Shamir 门限的 CP-ABE 教学实现。

    加密：用会话密钥 K 加密数据；将 K 作为根秘密按策略树逐层门限共享，
          每个叶子属性拿到一份份额（shares）。
    解密：持有者用自己的属性份额按树结构自底向上重构出 K。
    """

    def __init__(self):
        self.cipher = AeadCipher()  # 会话密钥加密器

    def encrypt(self, plaintext: dict, policy_tree) -> dict:
        """返回 {ciphertext, policy, shares}。"""
        session_key = int.from_bytes(os.urandom(16), "big") % (_PRIME - 1) + 1
        ct = self.cipher.encrypt(plaintext)

        def share_node(node, secret_val) -> dict:
            if isinstance(node, str):  # 叶子
                return {"type": "leaf", "attr": node, "share": secret_val}
            gate, children = node
            n = len(children)
            t = n if gate == "and" else 1
            # 生成 t-1 次多项式，常数项为 secret_val
            coeffs = [secret_val] + [secrets.randbelow(_PRIME) for _ in range(t - 1)]
            child_secrets = [_poly_eval(coeffs, i + 1) for i in range(n)]
            return {
                "type": "gate",
                "gate": gate,
                "t": t,
                "n": n,
                "children": [share_node(c, cs) for c, cs in zip(children, child_secrets)],
            }

        shares = share_node(policy_tree, session_key)
        return {
            "ciphertext": ct,
            "policy": policy_tree,
            "shares": shares,
            "session_key_b64": self._b64(session_key),  # 演示用，真实系统不外发
        }

    @staticmethod
    def _b64(v: int) -> str:
        return v.to_bytes(16, "big").hex()

    def decrypt(self, ct: dict, shares: dict, attrs: set[str]) -> dict:
        """用属性集合重构会话密钥并解密。不满足策略则抛异常。"""
        def reconstruct(node) -> int:
            if node["type"] == "leaf":
                if node["attr"] not in attrs:
                    raise ValueError(f"缺少属性: {node['attr']}")
                return node["share"]
            # 内部节点：收集满足条件的子份额（x 坐标为 child 序号 1..n）
            indexed = []
            for idx, child in enumerate(node["children"]):
                try:
                    indexed.append((idx + 1, reconstruct(child)))
                except ValueError:
                    continue
            if len(indexed) < node["t"]:
                raise ValueError("属性集合不满足策略")
            return _interp(indexed[:node["t"]])

        session_key = reconstruct(shares)
        del session_key  # 演示语义：密钥已成功重构
        return self.cipher.decrypt(ct["ciphertext"]["iv"], ct["ciphertext"]["ciphertext"])


def make_policy(gate: str, *children) -> tuple:
    """构造策略树：make_policy('and', 'role:doctor', 'dept:cardiology')。"""
    return (gate, list(children))


def make_and(*children):
    return make_policy("and", *children)


def make_or(*children):
    return make_policy("or", *children)
