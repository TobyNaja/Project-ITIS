"""
security_engine/health/runner.py — STEP 9B: thread ที่เดินรอบตรวจสุขภาพ (FR-12/FR-13)

    EVE reader ──on_stats──> HealthMonitor ──check()──> HealthRunner
                                                            │ DEGRADED
                                                            ▼
                                                      RecoveryManager
                                                            │
                                                            ▼
                                                     SuricataController

ทำไมต้องเป็น thread แยก (เหมือน LifecycleRunner):
main thread ค้างอยู่ที่ blocking readline ของ EVE stream — ถ้า Suricata ตาย
stream จะ "เงียบ" ไม่ใช่ "error" การตรวจสุขภาพจึงต้องเดินด้วยตัวเอง

หลักที่ล็อก:
- stop_event.wait(interval) -> shutdown ทันที ไม่ต้องรอครบ check_interval_sec
- exception ใน tick ต้องไม่ฆ่า thread และต้องไม่กระทบ event pipeline (NFR-02)
- CRITICAL = ยังเดินต่อ (ไม่ raise, ไม่หยุด engine) แต่ **หยุดพยายาม restart**
  จนกว่า health จะกลับมา HEALTHY เอง -> ดู CRITICAL_IS_LATCHED ด้านล่าง
"""
import logging
import threading

from security_engine.health.monitor import CRITICAL, DEGRADED, HEALTHY

log = logging.getLogger(__name__)

DEFAULT_INTERVAL_SEC = 15

# FR-13 บอกว่า retry ได้สูงสุด 3 ครั้ง — "3 ครั้งต่อเหตุการณ์" ไม่ใช่ "3 ครั้งต่อรอบตรวจ"
# ถ้าไม่ latch ไว้ รอบถัดไป (อีก 15 วิ) จะ restart ซ้ำอีก 3 ครั้งไปเรื่อย ๆ ไม่มีที่สิ้นสุด
# -> เข้าสู่ CRITICAL แล้วหยุดสั่ง restart รอจนกว่า monitor จะรายงาน HEALTHY เอง
#    (เช่น admin แก้ที่เครื่อง / Suricata กลับมาเขียน stats)
CRITICAL_IS_LATCHED = True


class HealthRunner:
    """เรียก monitor.check() ทุก interval แล้วส่งต่อให้ RecoveryManager เมื่อ DEGRADED"""

    def __init__(self, monitor, recovery=None, interval=DEFAULT_INTERVAL_SEC,
                 on_error=None):
        self.monitor = monitor
        self.recovery = recovery            # None = ตรวจอย่างเดียว ไม่กู้
        self.interval = interval
        self.on_error = on_error            # callable(exc) สำหรับ log
        self.state = HEALTHY
        self.last_status = None
        self.last_outcome = None
        self._stop = threading.Event()
        self._thread = None

    # ---- หนึ่งรอบตรวจ (เรียกตรง ๆ ได้ใน test ไม่ต้องใช้ thread) ----
    def tick(self):
        status = self.monitor.check()
        self.last_status = status

        if status.healthy:
            if self.state == CRITICAL:
                log.warning("Suricata กลับมา HEALTHY หลังอยู่ในสถานะ CRITICAL")
            self.state = HEALTHY
            return status

        if self.state == CRITICAL and CRITICAL_IS_LATCHED:
            # ครบเพดาน retry ของเหตุการณ์นี้แล้ว — ไม่สั่ง restart ซ้ำไม่รู้จบ
            log.error("Suricata ยังอยู่ในสถานะ CRITICAL (%s) — หยุด auto recovery "
                      "รอการแก้ไขที่เครื่อง IDS", status.failure_reason)
            return status

        if self.recovery is None:
            self.state = DEGRADED
            return status

        outcome = self.recovery.recover(status)
        self.last_outcome = outcome
        self.state = outcome.state
        return status

    # ---- thread ----
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="HealthRunner",
                                        daemon=True)
        self._thread.start()

    def run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:        # noqa: BLE001 — 1 error ห้ามฆ่า thread
                log.error("health check รอบนี้ล้มเหลว: %s", exc, exc_info=exc)
                if self.on_error is not None:
                    self.on_error(exc)
            self._stop.wait(self.interval)

    def stop(self, join=True, timeout=5.0):
        self._stop.set()
        if join and self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()
