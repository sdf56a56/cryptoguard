"""
OCR 异步隔离 worker(可选演示)

安全目标:OCR 输出仅供预览面板 —— 不进 input_hash、不修改任何已发请求、
不回流检测管线;主线永不 await OCR(submit_ocr 立即返回 task_id,poll_ocr 轮询)。
无 OCR 引擎(pytesseract/Tesseract 缺失)时返回 status=unavailable,主线不受影响。

明确不承诺:OCR 识别质量与召回;预览文本可能含未检出的敏感明文,不得外发。
隔离:worker 跑在独立单线程 ThreadPoolExecutor,异常一律收敛为 unavailable 结果。
"""
from __future__ import annotations

import io
import uuid
from concurrent.futures import ThreadPoolExecutor

# 单线程隔离:OCR 慢/挂起不占主线,也不并发挤占资源
_executor = ThreadPoolExecutor(max_workers=1)
# task_id -> None(进行中) | dict(终态);仅 worker 线程写,主线读
_results: dict[str, dict | None] = {}


def submit_ocr(data: bytes, filename: str) -> str:
    """提交 OCR 任务,立即返回 task_id(主线不阻塞、不 await)。"""
    task_id = uuid.uuid4().hex
    _results[task_id] = None                      # None = 进行中
    _executor.submit(_run, task_id, data, filename)
    return task_id


def poll_ocr(task_id: str) -> dict | None:
    """轮询任务结果:进行中/未知 task_id → None;终态 → 结果字典。

    终态字典:{"status":"done","preview_text":str,"redacted_preview":str}
    或 {"status":"unavailable","reason":"no-ocr-engine"}(无引擎,演示机常态)。
    """
    return _results.get(task_id)


def _run(task_id: str, data: bytes, filename: str) -> None:
    try:
        _results[task_id] = _do_ocr(data, filename)
    except Exception as exc:  # worker 内任何异常都不得逃逸影响主线
        _results[task_id] = {"status": "unavailable", "reason": f"ocr-error:{type(exc).__name__}"}


def _do_ocr(data: bytes, filename: str) -> dict:
    # 可选依赖:缺失即 unavailable(不安装 pytesseract,保持主线零依赖)
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return {"status": "unavailable", "reason": "no-ocr-engine"}
    try:
        img = Image.open(io.BytesIO(data))
        text = pytesseract.image_to_string(img)
    except Exception as exc:
        # 含 TesseractNotFoundError(库在引擎不在)与图像解析失败
        return {"status": "unavailable", "reason": f"no-ocr-engine:{type(exc).__name__}"}
    from .detection import detect_sensitive
    det = detect_sensitive(text)
    # 仅供预览面板:不进 input_hash、不修改任何已发请求
    return {"status": "done", "preview_text": text, "redacted_preview": det.redacted}
