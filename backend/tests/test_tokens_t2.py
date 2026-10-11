import re
from app.tokens import T2Cipher, id_check_digit, luhn_digit

c = T2Cipher(key=bytes(range(32)))

def test_id_roundtrip_and_checkdigit():
    d17 = "11010519491231002"          # 北京 1949-12-31
    ct = c.encrypt_id17(d17)
    assert re.fullmatch(r"\d{17}", ct)  # 保格式:17 位数字
    full = ct + id_check_digit(ct)
    assert re.fullmatch(r"\d{17}[\dXx]", full)   # 18 位含校验位(17 数字 + 校验位)
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
