from app.canon import h_hex
from app.tokenchain import (token_chain, file_content_hash,
                            override_hash, input_hash, response_hash,
                            input_hash_preimage)

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

def test_r8_input_hash_preimage_wrapper():
    args = ("text", ["fh1"], "root", override_hash([]), "nonce", "2026-10-11T00:00:00.000000Z")
    assert input_hash(*args) == h_hex(input_hash_preimage(*args))
