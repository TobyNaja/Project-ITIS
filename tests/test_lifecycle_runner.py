"""
tests/test_lifecycle_runner.py — Phase 11.2 LifecycleRunner (unit)

fake lifecycle + interval สั้น (0.05s) เพื่อไม่ต้องรอจริง
ครอบ 7 เคสที่ล็อก
"""
import threading
import time

from security_engine.lifecycle.runner import LifecycleRunner

INTERVAL = 0.05


class FakeLifecycle:
    """นับจำนวนครั้งที่ expire_due ถูกเรียก; toggle ให้ raise ได้"""
    def __init__(self, raise_on=None):
        self.calls = 0
        self.raise_on = raise_on            # เลขครั้งที่จะ raise (None = ไม่ raise)
        self._lock = threading.Lock()

    def expire_due(self, now=None):
        with self._lock:
            self.calls += 1
            n = self.calls
        if self.raise_on is not None and n == self.raise_on:
            raise RuntimeError("boom")

    def count(self):
        with self._lock:
            return self.calls


def _runner(life, **kw):
    return LifecycleRunner(life, threading.Lock(), interval=INTERVAL, **kw)


# ---- 1. start() ทำให้ thread ทำงาน ----
def test_start_runs_thread():
    life = FakeLifecycle()
    r = _runner(life)
    r.start()
    try:
        time.sleep(INTERVAL * 3)
        assert r.is_running()
        assert life.count() >= 1
    finally:
        r.stop()


# ---- 2. expire_due ถูกเรียกซ้ำตาม interval ----
def test_expire_called_repeatedly():
    life = FakeLifecycle()
    r = _runner(life)
    r.start()
    try:
        time.sleep(INTERVAL * 5)
    finally:
        r.stop()
    # ~5 interval ควรเรียกหลายครั้ง (เผื่อ jitter อย่างน้อย 3)
    assert life.count() >= 3


# ---- 3 + 4. stop() หยุด thread และ join สำเร็จ ----
def test_stop_stops_and_joins():
    life = FakeLifecycle()
    r = _runner(life)
    r.start()
    time.sleep(INTERVAL * 2)
    r.stop()                                # join=True default
    assert not r.is_running()
    after = life.count()
    time.sleep(INTERVAL * 3)
    assert life.count() == after            # ไม่เรียกเพิ่มหลัง stop


# ---- 5. ใช้ shared lock ตัวเดียวกับ pipeline ----
def test_uses_shared_lock():
    life = FakeLifecycle()
    shared = threading.Lock()
    r = LifecycleRunner(life, shared, interval=INTERVAL)
    # ถือ lock ไว้ก่อน -> runner ต้องรอ (expire_due ยังไม่ถูกเรียก)
    shared.acquire()
    r.start()
    try:
        time.sleep(INTERVAL * 3)
        assert life.count() == 0            # ถูก block ด้วย lock ที่เราถือ
    finally:
        shared.release()
        time.sleep(INTERVAL * 3)
        r.stop()
    assert life.count() >= 1                # ปล่อย lock แล้วเดินต่อ


# ---- 6. expire_due exception -> runner ไม่ตายเงียบ ----
def test_exception_does_not_kill_thread():
    errors = []
    life = FakeLifecycle(raise_on=1)        # ครั้งแรก raise
    r = _runner(life, on_error=errors.append)
    r.start()
    try:
        time.sleep(INTERVAL * 5)
        assert r.is_running()               # ยังรันอยู่แม้ครั้งแรก error
        assert len(errors) >= 1             # error ถูก log ไม่ถูกกลืน
        assert life.count() >= 2            # เรียกต่อหลัง error
    finally:
        r.stop()


# ---- 7. start() ซ้ำไม่สร้าง thread ใหม่ ----
def test_double_start_no_duplicate_thread():
    life = FakeLifecycle()
    r = _runner(life)
    r.start()
    t1 = r._thread
    r.start()                               # เรียกซ้ำโดยไม่ stop
    t2 = r._thread
    try:
        assert t1 is t2                     # thread เดิม ไม่สร้างใหม่
    finally:
        r.stop()


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-v"]))