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
