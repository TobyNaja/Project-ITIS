"""
tests/test_health_monitor.py — STEP 9A: functional health ของ Suricata (FR-12)

พิสูจน์ D6/D7 ของ Blueprint: health ไม่ใช่แค่ "process ยังอยู่"
    process ตาย            -> PROCESS_DOWN
    stats ไม่มาเกิน 8×3 วิ  -> EVE_STALE   (Suricata เขียน stats เป็นระยะ
                                            ไม่ขึ้นกับว่ามี traffic หรือไม่)
    เสียทั้งคู่            -> "PROCESS_DOWN;EVE_STALE" (ไม่ทิ้งสาเหตุใดสาเหตุหนึ่ง)

เวลาใน test ถูก inject ผ่าน clock -> ไม่มี sleep จริง ไม่มี flaky test
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.health.monitor import (
    DEGRADED,
    HEALTHY,
    REASON_EVE_STALE,
    REASON_PROCESS_DOWN,
    HealthMonitor,
    HealthStatus,
)

STATS_INTERVAL = 8          # config: health.stats_interval_sec
MULTIPLIER = 3              # config: health.stats_freshness_multiplier
FRESHNESS = STATS_INTERVAL * MULTIPLIER     # 24 วินาที

START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """นาฬิกาที่เดินเมื่อสั่งเท่านั้น"""

    def __init__(self, start=START):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)
        return self.now


class FakeController:
    def __init__(self, running=True):
        self.running = running
        self.is_running_calls = 0

    def is_running(self):
        self.is_running_calls += 1
        return self.running


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def controller():
    return FakeController(running=True)


@pytest.fixture
def monitor(controller, clock):
    return HealthMonitor(controller, stats_interval_sec=STATS_INTERVAL,
                         stats_freshness_multiplier=MULTIPLIER, clock=clock)


STATS_EVENT = {"event_type": "stats", "stats": {"uptime": 120}}


# ---- 1. เกณฑ์ความสดมาจาก config ----
def test_freshness_is_interval_times_multiplier(monitor):
    assert monitor.stats_freshness_sec == FRESHNESS == 24


def test_freshness_follows_config_not_hardcoded(controller, clock):
    m = HealthMonitor(controller, stats_interval_sec=10,
                      stats_freshness_multiplier=2, clock=clock)
    assert m.stats_freshness_sec == 20


# ---- 2. HEALTHY ----
def test_healthy_when_process_up_and_stats_fresh(monitor, clock):
    monitor.on_stats(STATS_EVENT)
    clock.advance(FRESHNESS - 1)
    status = monitor.check()
    assert status.state == HEALTHY
    assert status.healthy is True
    assert status.reasons == ()
    assert status.failure_reason is None
    assert status.process_running is True


def test_status_carries_stats_age_and_timestamp(monitor, clock):
    monitor.on_stats(STATS_EVENT)
    clock.advance(5)
    status = monitor.check()
    assert status.stats_age_sec == pytest.approx(5)
    assert status.checked_at == clock.now


# ---- 3. PROCESS_DOWN ----
def test_degraded_when_process_down(monitor, controller, clock):
    monitor.on_stats(STATS_EVENT)
    controller.running = False
    status = monitor.check()
    assert status.state == DEGRADED
    assert status.reasons == (REASON_PROCESS_DOWN,)
    assert status.failure_reason == REASON_PROCESS_DOWN
    assert status.process_running is False


# ---- 4. EVE_STALE ----
def test_degraded_when_stats_stale(monitor, clock):
    monitor.on_stats(STATS_EVENT)
    clock.advance(FRESHNESS + 1)
    status = monitor.check()
    assert status.state == DEGRADED
    assert status.reasons == (REASON_EVE_STALE,)
    assert status.process_running is True, "process ยังเดิน — ปัญหาอยู่ที่ stats"


def test_stats_exactly_at_threshold_is_still_fresh(monitor, clock):
    """ขอบเขต: อายุ = 24 วิพอดี ยังถือว่าสด (stale เมื่อ 'เกิน' เกณฑ์)"""
    monitor.on_stats(STATS_EVENT)
    clock.advance(FRESHNESS)
    assert monitor.check().state == HEALTHY


def test_new_stats_event_resets_age(monitor, clock):
    monitor.on_stats(STATS_EVENT)
    clock.advance(FRESHNESS + 5)
    assert monitor.check().state == DEGRADED
    monitor.on_stats(STATS_EVENT)                 # stats รอบใหม่มาถึง
    assert monitor.check().state == HEALTHY


def test_on_stats_records_last_event(monitor):
    monitor.on_stats(STATS_EVENT)
    assert monitor.last_stats_event is STATS_EVENT
    assert monitor.last_stats_at is not None


# ---- 5. เสียพร้อมกันสองอย่าง -> เก็บครบทั้งสองสาเหตุ ----
def test_both_reasons_recorded_in_order(monitor, controller, clock):
    controller.running = False
    clock.advance(FRESHNESS + 10)
    status = monitor.check()
    assert status.reasons == (REASON_PROCESS_DOWN, REASON_EVE_STALE)
    assert status.failure_reason == "PROCESS_DOWN;EVE_STALE"


# ---- 6. ช่วงเริ่มทำงาน: ยังไม่เคยได้ stats ----
# grace = "ยังไม่ถึงเวลาที่ควรเห็น stats ตัวแรก" เท่านั้น
# ห้ามกลายเป็น permanent exemption ว่า "ไม่เคยมี stats = HEALTHY ตลอด" (ขัด FR-12)
def test_startup_grace_before_first_stats(monitor, clock):
    """เพิ่งสตาร์ต ยังไม่เคยเห็น stats -> ต้องไม่ DEGRADED ทันที"""
    clock.advance(1)
    assert monitor.check().state == HEALTHY


def test_startup_grace_ends_exactly_at_freshness_threshold(monitor, clock):
    """grace ใช้เกณฑ์เดียวกับ stats ปกติ (24s) ไม่ใช่เกณฑ์พิเศษของตัวเอง"""
    clock.advance(FRESHNESS)
    assert monitor.check().state == HEALTHY          # 24s พอดี = ยังอยู่ใน grace
    clock.advance(1)                                  # 25s
    assert monitor.check().state == DEGRADED


def test_no_stats_after_grace_is_stale(monitor, clock):
    clock.advance(FRESHNESS + 1)
    assert monitor.check().reasons == (REASON_EVE_STALE,)


def test_grace_is_not_permanent_exemption(monitor, controller, clock):
    """process เดินอยู่ แต่ไม่เคยมี stats เลย -> ต้อง DEGRADED และคงอยู่แบบนั้น

    กันเคสที่ implementation เผลอตีความว่า last_stats_at is None = ยกเว้นตลอดไป
    """
    assert controller.running is True
    for elapsed in (FRESHNESS + 1, 60, 300, 3600):
        clock.advance(elapsed)
        status = monitor.check()
        assert status.state == DEGRADED, f"ผ่านมา {elapsed}s แล้วยังบอก HEALTHY"
        assert status.reasons == (REASON_EVE_STALE,)
        assert status.process_running is True


def test_first_stats_after_grace_restores_health(monitor, clock):
    """เคย DEGRADED เพราะไม่มี stats แล้ว stats ตัวแรกมาถึง -> กลับมา HEALTHY"""
    clock.advance(FRESHNESS + 10)
    assert monitor.check().state == DEGRADED
    monitor.on_stats(STATS_EVENT)
    assert monitor.check().state == HEALTHY


# ---- 7. monitor ไม่ทำ I/O เอง นอกจากถาม controller ----
def test_check_asks_controller_once(monitor, controller):
    monitor.check()
    assert controller.is_running_calls == 1


def test_monitor_has_no_internal_loop(monitor):
    """ไม่มี loop ถาวรใน monitor — HealthRunner (STEP 9B) เป็นคนเรียกตามรอบ"""
    assert not hasattr(monitor, "run")
    assert not hasattr(monitor, "start")


# ---- 8. HealthStatus ----
def test_status_str_is_readable():
    text = str(HealthStatus(state=DEGRADED, reasons=(REASON_EVE_STALE,),
                            stats_age_sec=30.0, process_running=True))
    assert DEGRADED in text and REASON_EVE_STALE in text


def test_status_is_immutable():
    status = HealthStatus(state=HEALTHY)
    with pytest.raises(Exception):
        status.state = DEGRADED


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
