"""
文件双通道 —— 抽取/默认拒绝路由/存证(spec §2)

安全目标:检测不可信的内容不进可读通道;原始文件永不出本地,存证三件套可验
(file_hash 原始字节锚 + vault_ct 密文元数据 + filename_token 伪名)。
明确不承诺:抽取丢字不保真;OCR 质量不在本模块;漏检实体仍会明文出站(检测召回率的函数)。

路由策略(SEC-FROUTE):默认拒绝 —— 抽取失败/为空、非白名单扩展名,一律只走存证;
只有白名单格式且抽出非空文本才进可读通道。

哈希口径(裁定 R24 衔接):
  - file_hash        = SHA-256(原始字节),存证锚点(FilePayload.file_hash);
  - file_content_hash = tokenchain.file_content_hash(字节按 latin-1 双射解码),
    内容绑定哈希,供 evidence 级 FilePayload.file_content_hash 声明并原样进
    input_hash 哈希序列。latin-1 与字节一一映射,任意字节变化必改哈希;
    刻意不用 utf-8 errors=replace(非法字节都归并 U+FFFD,二进制会碰撞)。
"""
from __future__ import annotations
import hashlib
from typing import Literal

from .tokenchain import file_content_hash

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 50_000

# 默认拒绝路由白名单(可读通道仅限这些扩展名)
_READABLE_EXT = (".txt", ".md", ".csv", ".docx", ".pdf")


def extract_text(data: bytes, filename: str) -> tuple[str, str]:
    """按扩展名分派抽取器,返回 (文本, 抽取器名)。

    失败/为空返回 ("", 原因):原因以 "extract-error:" 开头表示抽取器异常,
    "unsupported" 表示无对应抽取器。超 MAX_FILE_BYTES 直接 ValueError(拒绝)。
    """
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
    if not filename.lower().endswith(_READABLE_EXT):
        return "evidence"
    return "readable"


def evidence_bundle(data: bytes, filename: str, aead,
                    filename_token: str | None = None) -> dict:
    """存证三件套 + 内容绑定哈希(裁定 R4:filename_token 可选参数,原样进返回字典)。

    原始文件不出本地:aead.encrypt 只封 filename/size 元数据,正文靠
    file_hash/file_content_hash 承诺,由持有原件者可复算验证。
    """
    return {
        "content_tier": "evidence",
        "file_hash": hashlib.sha256(data).hexdigest(),
        "file_content_hash": file_content_hash(data.decode("latin-1")),
        "vault_ct": aead.encrypt({"filename": filename, "size": len(data)}),
        "filename_token": filename_token,
    }
