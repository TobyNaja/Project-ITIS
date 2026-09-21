"""
security_engine/lifecycle/runner.py — Phase 11.2 LifecycleRunner

Thread แยกที่เรียก lifecycle.expire_due() เป็นระยะ — แก้ปัญหา
"expiry ต้องทำงานแม้ EVE event เงียบ" (main thread ค้างที่ blocking readline)

หลักที่ล็อก:
- stop_event.wait(interval) แทน time.sleep -> shutdown ได้ทันที ไม่ต้องรอครบ interval
- lock เฉพาะตอนเรียก lifecycle operation (แชร์กับ Pipeline) ไม่ล็อกทั้งรอบ thread
- expire_due() error -> log ผ่าน on_error callback แล้ว loop ต่อ (ไม่ตายเงียบ)
  Phase 13 ค่อยยกระดับ recovery
- start() ซ้ำโดยไม่ stop ก่อน -> ไม่สร้าง thread ซ้ำ
"""
import threading


class LifecycleRunner:
    def __init__(self, lifecycle, lock, interval=1.0, on_error=None):
        self.lifecycle = lifecycle
        self.lock = lock                    # shared กับ Pipeline
        self.interval = interval
        self.on_error = on_error            # callable(exc) สำหรับ log; None = เงียบแต่ไม่ตาย
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        # กันสร้าง thread ซ้ำถ้ายังรันอยู่
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="LifecycleRunner",
                                        daemon=True)
        self._thread.start()

    def run(self):
        """loop ภายใน thread — เรียก expire_due ทุก interval จนกว่าจะ stop"""
        while not self._stop.is_set():
            try:
                with self.lock:             # ล็อกเฉพาะตอน operation
                    self.lifecycle.expire_due()
            except Exception as exc:        # ไม่ให้ 1 error ฆ่า thread
                if self.on_error is not None:
                    self.on_error(exc)
            # ปลุกทันทีเมื่อ stop() — ไม่ต้องรอครบ interval
            self._stop.wait(self.interval)

    def stop(self, join=True, timeout=5.0):
        self._stop.set()
        if join and self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()