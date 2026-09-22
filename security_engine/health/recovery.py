"""
security_engine/health/recovery.py — Suricata recovery (FR-13 / O10 / M10)

    DEGRADED -> attempt 1..max: restart -> รอ -> functional check
                 สำเร็จ -> SUCCESS (HEALTHY)
                 ล้มครบ -> CRITICAL + ALERT   *** ไม่มี attempt ที่ max+1 ***

หลักที่ล็อก:
- **command success ≠ functional recovery** — restart คืน rc=0 ยังไม่พอ
  ต้องตรวจซ้ำว่า process เดินจริง **และ** stats กลับมาสด (HealthMonitor.check())
- ทุก attempt เขียนลง recovery_events (§3.4) ไม่ว่าจะ SUCCESS/FAIL/CRITICAL
  -> M10 (Recovery Success Rate) คำนวณจาก DB ได้จริง
- CRITICAL เป็น "สถานะสุขภาพ + เงื่อนไขแจ้งเตือน" **ไม่ใช่** การหยุด engine
  pipeline/expiry/audit ต้องทำงานต่อ (Blueprint ไม่ได้กำหนด fail-stop)
- ไม่มี loop ถาวรในนี้ — HealthRunner เป็นคนเรียกตามรอบ
"""
import logging
import time
from dataclasses import dataclass, field

from security_engine.health.monitor import CRITICAL, DEGRADED, HEALTHY

log = logging.getLogger(__name__)

SERVICE_SURICATA = "suricata"

RESULT_SUCCESS = "SUCCESS"      # ตรงกับ recovery_events.result (§3.4)
RESULT_FAIL = "FAIL"
RESULT_CRITICAL = "CRITICAL"

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RESTART_WAIT_SEC = 5


@dataclass(frozen=True)
class RecoveryOutcome:
    state: str                      # HEALTHY (กู้สำเร็จ) หรือ CRITICAL
    attempts: int = 0
    results: tuple = field(default_factory=tuple)   # ผลของแต่ละ attempt ตามลำดับ
    failure_reason: str = None

    @property
    def recovered(self) -> bool:
        return self.state == HEALTHY

    def __str__(self):
        return (f"[RECOVERY] {self.state} attempts={self.attempts} "
                f"reason={self.failure_reason or '-'}")


class RecoveryManager:
    """กู้ Suricata ตาม FR-13 — restart + functional check + retry ≤ max_attempts"""

    def __init__(self, controller, monitor, repository=None,
                 max_attempts=DEFAULT_MAX_ATTEMPTS,
                 restart_wait_sec=DEFAULT_RESTART_WAIT_SEC,
                 sleep=time.sleep):
        self.controller = controller
        self.monitor = monitor
        self.repository = repository        # None = ไม่บันทึก audit (unit test)
        self.max_attempts = max_attempts
        self.restart_wait_sec = restart_wait_sec
        self.sleep = sleep                  # inject ได้ -> test ไม่ต้องรอจริง

    # ---- audit ----
    def _record(self, attempt, result, failure_reason, error=None):
        """เขียน recovery_events — audit ล้มต้องไม่ทำให้การกู้ล้มตาม (NFR-06)"""
        if self.repository is None:
            return
        try:
            self.repository.save_recovery_event(
                service=SERVICE_SURICATA, failure_reason=failure_reason,
                attempt=attempt, result=result, error=error)
        except Exception as exc:            # noqa: BLE001 — audit boundary
            log.error("บันทึก recovery_events ไม่สำเร็จ (attempt %s, %s): %s",
                      attempt, result, exc)

    # ---- main ----
    def recover(self, status) -> RecoveryOutcome:
        """รับ HealthStatus ที่ DEGRADED แล้วพยายามกู้

        คืน RecoveryOutcome — HEALTHY ถ้ากู้ได้, CRITICAL ถ้าล้มครบ max_attempts
        """
        if status is not None and status.state == HEALTHY:
            log.debug("health ปกติอยู่แล้ว — ไม่ต้องกู้")
            return RecoveryOutcome(state=HEALTHY, attempts=0)

        failure_reason = getattr(status, "failure_reason", None) or DEGRADED
        results = []

        for attempt in range(1, self.max_attempts + 1):
            log.warning("เริ่ม recovery Suricata attempt %s/%s (%s)",
                        attempt, self.max_attempts, failure_reason)

            restart = self.controller.restart()
            error = None if restart.ok else restart.error

            if restart.ok:
                # command success ≠ functional recovery -> ต้องตรวจซ้ำ
                self.sleep(self.restart_wait_sec)
                verified = self.monitor.check()
                if verified.healthy:
                    results.append(RESULT_SUCCESS)
                    self._record(attempt, RESULT_SUCCESS, failure_reason)
                    log.info("recovery Suricata สำเร็จที่ attempt %s/%s",
                             attempt, self.max_attempts)
                    return RecoveryOutcome(state=HEALTHY, attempts=attempt,
                                           results=tuple(results),
                                           failure_reason=failure_reason)
                error = f"functional check ยังไม่ผ่าน: {verified.failure_reason}"

            last_attempt = attempt == self.max_attempts
            result = RESULT_CRITICAL if last_attempt else RESULT_FAIL
            results.append(result)
            self._record(attempt, result, failure_reason, error=error)

            if last_attempt:
                # FR-13: ครบเพดานแล้วหยุด ไม่มี attempt ถัดไป + ALERT ทันที
                log.critical("recovery Suricata ล้มครบ %s ครั้ง (%s) — CRITICAL "
                             "engine ทำงานต่อแต่ IDS อาจไม่ส่ง event แล้ว",
                             self.max_attempts, error or failure_reason)
            else:
                log.error("recovery attempt %s/%s ล้มเหลว: %s",
                          attempt, self.max_attempts, error)

        return RecoveryOutcome(state=CRITICAL, attempts=self.max_attempts,
                               results=tuple(results), failure_reason=failure_reason)
