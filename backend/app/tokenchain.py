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


def input_hash_preimage(redacted_text: str, file_hashes: list[str], token_root: str,
                        override_h: str, nonce: str, timestamp: str) -> dict:
    """input_hash 的精确前映像(R8:调用方可审计/复现 input_hash)。"""
    return {
        "d": D_INPUT,
        "t": h_hex({"d": D_TEXT, "x": redacted_text}),
        "f": file_hashes,
        "r": token_root,
        "o": override_h,
        "n": nonce,
        "ts": timestamp,
    }


def input_hash(redacted_text: str, file_hashes: list[str], token_root: str,
               override_h: str, nonce: str, timestamp: str) -> str:
    return h_hex(input_hash_preimage(redacted_text, file_hashes, token_root,
                                    override_h, nonce, timestamp))


def response_hash(output: str, input_hash_v: str, model_cert: dict,
                  nonce: str, timestamp: str) -> str:
    return h_hex({"d": D_RESP, "out": output, "ih": input_hash_v,
                  "cert": model_cert, "n": nonce, "ts": timestamp})
