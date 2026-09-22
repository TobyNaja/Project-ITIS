"""
security_engine/health/monitor.py — Functional health ของ Suricata (FR-12)

    SuricataController.is_running()  ──┐
                                        ├─> HealthMonitor.check() -> HealthStatus
    EVE reader on_stats -> last_stats_at┘

D6/D7 ของ Blueprint: health = **functional** ไม่ใช่แค่ process ยังอยู่
    - process ตาย                      -> PROCESS_DOWN
    - stats ไม่มาเกิน stats_interval × N -> EVE_STALE (network เงียบ ≠ Suricata เสีย
      เพราะ Suricata เขียน stats เป็นระยะไม่ขึ้นกับ traffic)

state ที่ล็อก: HEALTHY / DEGRADED / CRITICAL
    HEALTHY  = process running **และ** stats สด
    DEGRADED = อย่างใดอย่างหนึ่งเสีย
    CRITICAL = recovery ล้มครบ max_attempts (RecoveryManager เป็นคนตั้ง)

*** ไม่มี loop ในนี้ *** — HealthRunner เป็นคนเรียก check() ตาม check_interval_sec
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger(__name__)

HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
CRITICAL = "CRITICAL"

REASON_PROCESS_DOWN = "PROCESS_DOWN"    # ตรงกับ recovery_events.failure_reason (§3.4)
REASON_EVE_STALE = "EVE_STALE"


def _utc_now():
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class HealthStatus:
    state: str
    reasons: tuple = field(default_factory=tuple)
    stats_age_sec: float = None
    process_running: bool = True
    checked_at: datetime = None

    @property
    def healthy(self) -> bool:
        return self.state == HEALTHY

    @property
    def failure_reason(self):
        """รูปแบบที่เขียนลง recovery_events — เสียหลายอย่างต้องเก็บครบ ไม่ทิ้งสาเหตุ"""
        return ";".join(self.reasons) if self.reasons else None

    def __str__(self):
        age = "n/a" if self.stats_age_sec is None else f"{self.stats_age_sec:.1f}s"
        return (f"[HEALTH] {self.state} process={self.process_running} "
                f"stats_age={age} reasons={self.failure_reason or '-'}")


class HealthMonitor:
    """รวมสัญญาณสองทาง (process + stats) เป็นสถานะเดียว

    stats_interval_sec / stats_freshness_multiplier มาจาก config เท่านั้น
    (ห้าม hardcode 8/3 ในนี้ — ค่าจริงของ lab ต้องยืนยันตอน dry run)
    """

    def __init__(self, controller, stats_interval_sec, stats_freshness_multiplier,
                 clock=_utc_now):
        self.controller = controller
        self.stats_interval_sec = stats_interval_sec
        self.stats_freshness_multiplier = stats_freshness_multiplier
        self.clock = clock
        self.last_stats_at = None
        self.last_stats_event = None
        # ยังไม่เคยเห็น stats เลย -> นับอายุจากเวลาที่เริ่มทำงาน ไม่ใช่ DEGRADED ทันที
        self.started_at = clock()

    # ---- ข้อมูลจาก EVE reader ----
    def on_stats(self, event):
        """callback ของ eve_reader — stats ไม่เข้า correlation/risk แต่ต่ออายุ health"""
        self.last_stats_at = self.clock()
        self.last_stats_event = event
        log.debug("ได้รับ EVE stats event (uptime=%s)",
                  (event or {}).get("stats", {}).get("uptime"))

    # ---- เกณฑ์ ----
    @property
    def stats_freshness_sec(self) -> int:
        return self.stats_interval_sec * self.stats_freshness_multiplier

    def stats_age_sec(self):
        """อายุของ stats ล่าสุด (วินาที) — ถ้ายังไม่เคยได้รับ นับจาก started_at"""
        reference = self.last_stats_at or self.started_at
        return (self.clock() - reference).total_seconds()

    def stats_fresh(self) -> bool:
        return self.stats_age_sec() <= self.stats_freshness_sec

    # ---- ตรวจสุขภาพ ----
    def check(self) -> HealthStatus:
        process_running = bool(self.controller.is_running())
        age = self.stats_age_sec()
        fresh = age <= self.stats_freshness_sec

        reasons = []
        if not process_running:
            reasons.append(REASON_PROCESS_DOWN)
        if not fresh:
            reasons.append(REASON_EVE_STALE)

        status = HealthStatus(
            state=HEALTHY if not reasons else DEGRADED,
            reasons=tuple(reasons),
            stats_age_sec=age,
            process_running=process_running,
            checked_at=self.clock(),
        )
        if reasons:
            log.warning("Suricata health = DEGRADED (%s, stats_age=%.1fs/%ss)",
                        status.failure_reason, age, self.stats_freshness_sec)
        else:
            log.debug("Suricata health = HEALTHY (stats_age=%.1fs)", age)
        return status
