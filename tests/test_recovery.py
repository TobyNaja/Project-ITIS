"""
tests/test_recovery.py — STEP 9A: auto recovery ของ Suricata (FR-13 / O10 / M10)

สัญญาที่ต้องผ่าน:
1. command success ≠ functional recovery
   restart คืน rc=0 แล้วยังต้องตรวจซ้ำด้วย HealthMonitor.check() ว่ากลับมาจริง
2. retry ไม่เกิน recovery.max_attempts และ **ไม่มี attempt ที่ max+1**
3. ทุก attempt ถูกบันทึกลง recovery_events -> M10 คำนวณจาก DB ได้
4. CRITICAL = สถานะ + เงื่อนไขแจ้งเตือน ไม่ใช่การหยุด engine
5. audit ล้ม ≠ recovery ล้ม (NFR-06)
"""
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.health.monitor import (
    CRITICAL,
    DEGRADED,
    HEALTHY,
    REASON_EVE_STALE,
    REASON_PROCESS_DOWN,
    HealthMonitor,
    HealthStatus,
)
from security_engine.health.recovery import (
    RESULT_CRITICAL,
    RESULT_FAIL,
    RESULT_SUCCESS,
    SERVICE_SURICATA,
    RecoveryManager,
)
from security_engine.health.suricata_controller import RestartResult
from security_engine.storage.repository import AuditRepository

RESTART_CMD = "/usr/local/etc/rc.d/suricata restart"
WAIT_SEC = 5
T_RESTART = datetime(2026, 9, 23, 16, 1, 56, tzinfo=timezone.utc)

DOWN = HealthStatus(state=DEGRADED, reasons=(REASON_PROCESS_DOWN,),
                    process_running=False, stats_age_sec=2.0)
STALE = HealthStatus(state=DEGRADED, reasons=(REASON_EVE_STALE,),
                     process_running=True, stats_age_sec=40.0)
RECOVERED = HealthStatus(state=HEALTHY, process_running=True, stats_age_sec=1.0)


class FakeController:
    """restart() คืนผลตามสคริปต์ที่กำหนด (ค่าสุดท้ายใช้ซ้ำถ้าถูกเรียกเกิน)"""

    def __init__(self, results=None):
        self.results = list(results or [RestartResult(ok=True, command=RESTART_CMD,
                                                      returncode=0)])
        self.calls = 0

    def restart(self):
        self.calls += 1
        index = min(self.calls - 1, len(self.results) - 1)
        return self.results[index]


class FakeMonitor:
    """check() คืน HealthStatus ตามสคริปต์ (ค่าสุดท้ายใช้ซ้ำ)

    stats_freshness_sec = WAIT_SEC -> ตรวจรอบเดียวต่อ attempt (เพดาน polling = 1 รอบ)
    test ของ polling หลายรอบอยู่ในส่วนที่ 8 (ใช้ HealthMonitor จริง)"""

    stats_freshness_sec = WAIT_SEC

    def __init__(self, statuses=None):
        self.statuses = list(statuses or [RECOVERED])
        self.calls = 0
        self.since = []

    def clock(self):
        return T_RESTART

    def check(self, since=None):
        self.since.append(since)
        self.calls += 1
        index = min(self.calls - 1, len(self.statuses) - 1)
        return self.statuses[index]


class SleepSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)


def build(controller=None, monitor=None, repository=None, max_attempts=3):
    sleeper = SleepSpy()
    manager = RecoveryManager(
        controller or FakeController(),
        monitor or FakeMonitor(),
        repository=repository,
        max_attempts=max_attempts,
        restart_wait_sec=WAIT_SEC,
        sleep=sleeper)
    return manager, sleeper


# ---- 1. กู้สำเร็จรอบแรก ----
def test_recovers_on_first_attempt():
    manager, sleeper = build()
    outcome = manager.recover(DOWN)
    assert outcome.state == HEALTHY
    assert outcome.recovered is True
    assert outcome.attempts == 1
    assert outcome.results == (RESULT_SUCCESS,)
    assert manager.controller.calls == 1
    assert sleeper.calls == [WAIT_SEC], "ต้องรอ restart_wait_sec ก่อนตรวจซ้ำ"


def test_healthy_status_needs_no_recovery():
    manager, sleeper = build()
    outcome = manager.recover(RECOVERED)
    assert outcome.state == HEALTHY
    assert outcome.attempts == 0
    assert manager.controller.calls == 0
    assert sleeper.calls == []


# ---- 2. command success != functional recovery ----
def test_restart_ok_but_still_degraded_counts_as_failure():
    """rc=0 แต่ตรวจซ้ำแล้วยัง DEGRADED -> ห้ามนับว่ากู้สำเร็จ"""
    monitor = FakeMonitor([STALE, STALE, STALE])
    manager, _ = build(monitor=monitor)
    outcome = manager.recover(DOWN)
    assert outcome.state == CRITICAL
    assert outcome.recovered is False
    assert monitor.calls == 3, "ต้องตรวจซ้ำทุก attempt ที่ restart สำเร็จ"


def test_recovers_on_second_attempt():
    manager, sleeper = build(monitor=FakeMonitor([STALE, RECOVERED]))
    outcome = manager.recover(DOWN)
    assert outcome.state == HEALTHY
    assert outcome.attempts == 2
    assert outcome.results == (RESULT_FAIL, RESULT_SUCCESS)
    assert sleeper.calls == [WAIT_SEC, WAIT_SEC]


# ---- 3. เพดาน retry ----
def test_stops_exactly_at_max_attempts():
    controller = FakeController()
    manager, _ = build(controller=controller, monitor=FakeMonitor([STALE]))
    outcome = manager.recover(DOWN)
    assert controller.calls == 3, "ห้ามมี attempt ที่ 4"
    assert outcome.attempts == 3
    assert outcome.results == (RESULT_FAIL, RESULT_FAIL, RESULT_CRITICAL)


def test_max_attempts_follows_config():
    controller = FakeController()
    manager, _ = build(controller=controller, monitor=FakeMonitor([STALE]),
                       max_attempts=1)
    outcome = manager.recover(DOWN)
    assert controller.calls == 1
    assert outcome.results == (RESULT_CRITICAL,)


# ---- 4. restart command ล้มเหลว (เช่นยังไม่ได้ตั้ง restart_command) ----
def test_failed_restart_skips_functional_check():
    failed = RestartResult(ok=False, command="", error="ยังไม่ได้ตั้ง restart_command")
    monitor = FakeMonitor([RECOVERED])
    manager, sleeper = build(controller=FakeController([failed]), monitor=monitor)
    outcome = manager.recover(DOWN)
    assert outcome.state == CRITICAL
    assert monitor.calls == 0, "restart ไม่สำเร็จ ไม่ต้องเสียเวลารอ/ตรวจซ้ำ"
    assert sleeper.calls == []


def test_critical_is_logged_not_raised(caplog):
    manager, _ = build(monitor=FakeMonitor([STALE]))
    with caplog.at_level("CRITICAL"):
        outcome = manager.recover(DOWN)      # ต้องไม่ raise -> engine ทำงานต่อ
    assert outcome.state == CRITICAL
    assert any(r.levelname == "CRITICAL" for r in caplog.records)


# ---- 5. audit: recovery_events (M10) ----
class RecordingRepo:
    def __init__(self):
        self.rows = []

    def save_recovery_event(self, **kwargs):
        self.rows.append(kwargs)
        return len(self.rows)


def test_every_attempt_is_recorded():
    repo = RecordingRepo()
    manager, _ = build(monitor=FakeMonitor([STALE]), repository=repo)
    manager.recover(DOWN)
    assert [r["attempt"] for r in repo.rows] == [1, 2, 3]
    assert [r["result"] for r in repo.rows] == [RESULT_FAIL, RESULT_FAIL,
                                                RESULT_CRITICAL]
    assert {r["service"] for r in repo.rows} == {SERVICE_SURICATA}


def test_success_attempt_is_recorded_with_reason():
    repo = RecordingRepo()
    manager, _ = build(monitor=FakeMonitor([STALE, RECOVERED]), repository=repo)
    manager.recover(DOWN)
    assert [r["result"] for r in repo.rows] == [RESULT_FAIL, RESULT_SUCCESS]
    assert all(r["failure_reason"] == REASON_PROCESS_DOWN for r in repo.rows)


def test_combined_failure_reason_is_preserved():
    repo = RecordingRepo()
    both = HealthStatus(state=DEGRADED,
                        reasons=(REASON_PROCESS_DOWN, REASON_EVE_STALE),
                        process_running=False, stats_age_sec=99.0)
    manager, _ = build(repository=repo)
    manager.recover(both)
    assert repo.rows[0]["failure_reason"] == "PROCESS_DOWN;EVE_STALE"


def test_failed_attempt_records_error_detail():
    repo = RecordingRepo()
    failed = RestartResult(ok=False, command="", error="restart_command ว่าง")
    manager, _ = build(controller=FakeController([failed]), repository=repo,
                       max_attempts=1)
    manager.recover(DOWN)
    assert "restart_command" in repo.rows[0]["error"]


# ---- 6. audit ล้ม != recovery ล้ม (NFR-06) ----
class BrokenRepo:
    def save_recovery_event(self, **kwargs):
        raise sqlite3.OperationalError("database is locked")


def test_audit_failure_does_not_break_recovery(caplog):
    manager, _ = build(repository=BrokenRepo())
    with caplog.at_level("ERROR"):
        outcome = manager.recover(DOWN)
    assert outcome.state == HEALTHY, "DB ล้มต้องไม่ทำให้ผลการกู้เปลี่ยน"
    assert any("recovery_events" in r.getMessage() for r in caplog.records)


def test_recovery_works_without_repository():
    manager, _ = build(repository=None)
    assert manager.recover(DOWN).state == HEALTHY


# ---- 7. เขียนลง SQLite จริง -> M10 คำนวณได้ ----
def test_recovery_events_persisted_for_m10(tmp_path):
    db_path = str(tmp_path / "recovery.db")
    repo = AuditRepository(db_path)

    ok, _ = build(repository=repo)                                  # สำเร็จ 1 ครั้ง
    ok.recover(DOWN)
    bad, _ = build(monitor=FakeMonitor([STALE]), repository=repo)    # ล้ม 3 ครั้ง
    bad.recover(STALE)

    rows = repo.get_recovery_events(service=SERVICE_SURICATA)
    assert len(rows) == 4
    assert [r["result"] for r in rows] == [RESULT_SUCCESS, RESULT_FAIL,
                                           RESULT_FAIL, RESULT_CRITICAL]
    assert rows[0]["failure_reason"] == REASON_PROCESS_DOWN
    assert rows[1]["failure_reason"] == REASON_EVE_STALE
    assert all(r["timestamp"] for r in rows)

    # M10 = เหตุการณ์ที่จบด้วย SUCCESS / เหตุการณ์ที่พยายามกู้ทั้งหมด
    with sqlite3.connect(db_path) as conn:
        counts = dict(conn.execute(
            "SELECT result, COUNT(*) FROM recovery_events GROUP BY result"))
    assert counts == {RESULT_SUCCESS: 1, RESULT_FAIL: 2, RESULT_CRITICAL: 1}


# ---- 8. recovery ต้องเห็น stats ของ process ใหม่ (defect ที่พบใน lab 2026-09-23) ----
# lab: stop 16:01:53 -> stats สุดท้ายของ process เก่า (uptime=147) 16:01:54 -> restart
# 16:01:56 -> ตรวจที่ +5s เห็น stats_age=9.6s -> SUCCESS ทั้งที่ stats แรกของ process
# ใหม่ (uptime=10) เพิ่งมา 16:02:08
def test_recovery_checks_against_restart_time():
    monitor = FakeMonitor()
    manager, _ = build(monitor=monitor)
    manager.recover(DOWN)
    assert monitor.since == [T_RESTART], "functional check ต้องอ้างเวลาที่สั่ง restart"


class LabClock:
    def __init__(self, start):
        self.now = start

    def __call__(self):
        return self.now


class RunningController:
    """process กลับมาหลัง restart เสมอ — ส่วนที่ทดสอบคือเงื่อนไข stats"""

    def __init__(self):
        self.restarts = 0

    def is_running(self):
        return True

    def restart(self):
        self.restarts += 1
        return RestartResult(ok=True, command=RESTART_CMD, returncode=0)


def stats(uptime):
    return {"event_type": "stats", "stats": {"uptime": uptime}}


def lab_recovery(schedule, max_attempts=3):
    """schedule = [(วินาทีหลัง restart ครั้งแรก, uptime)] — stats ที่มาถึงระหว่างรอ
    stats ของ process เก่า (uptime=147) มาถึงก่อน restart 2 วินาที"""
    clock = LabClock(T_RESTART - timedelta(seconds=2))
    controller = RunningController()
    monitor = HealthMonitor(controller, stats_interval_sec=10,
                            stats_freshness_multiplier=3, clock=clock)
    monitor.on_stats(stats(147))
    clock.now = T_RESTART
    pending = sorted(schedule)

    def sleep(seconds):
        target = clock.now + timedelta(seconds=seconds)
        while pending and T_RESTART + timedelta(seconds=pending[0][0]) <= target:
            offset, uptime = pending.pop(0)
            clock.now = T_RESTART + timedelta(seconds=offset)
            monitor.on_stats(stats(uptime))
        clock.now = target

    manager = RecoveryManager(controller, monitor, max_attempts=max_attempts,
                              restart_wait_sec=WAIT_SEC, sleep=sleep)
    return manager, controller


def test_old_process_stats_do_not_count_as_recovery():
    """stats ของ process เก่ายังสด (<30s) แต่ไม่มี stats ใหม่ -> ห้าม SUCCESS"""
    manager, controller = lab_recovery(schedule=[], max_attempts=1)
    outcome = manager.recover(DOWN)
    assert outcome.state == CRITICAL
    assert outcome.results == (RESULT_CRITICAL,)
    assert controller.restarts == 1


def test_recovery_waits_for_first_stats_of_new_process():
    """lab จริง: stats แรกของ process ใหม่มาที่ +12s (uptime=10) -> SUCCESS attempt 1"""
    manager, controller = lab_recovery(schedule=[(12, 10)])
    outcome = manager.recover(DOWN)
    assert outcome.state == HEALTHY
    assert outcome.results == (RESULT_SUCCESS,)
    assert controller.restarts == 1, "รอ stats ใหม่ ไม่ใช่ restart ซ้ำ"


def test_shutdown_flush_after_restart_is_not_new_stats():
    """restart ที่หยุด process เก่าเอง -> stats flush (uptime สูง) มาหลังสั่ง restart
    ต้องไม่ถูกนับเป็นของ process ใหม่"""
    manager, _ = lab_recovery(schedule=[(1, 147)], max_attempts=1)
    assert manager.recover(STALE).state == CRITICAL

    manager, _ = lab_recovery(schedule=[(1, 147), (11, 10)])
    assert manager.recover(STALE).results == (RESULT_SUCCESS,)


def test_no_new_stats_within_freshness_window_fails_attempt(tmp_path):
    """เพดานรอ = stats_freshness_sec (30s) -> เลยแล้วยังไม่มี stats ใหม่ = attempt ล้ม"""
    repo = AuditRepository(str(tmp_path / "r.db"))
    manager, _ = lab_recovery(schedule=[(31, 30)], max_attempts=1)
    manager.repository = repo
    outcome = manager.recover(DOWN)
    assert outcome.state == CRITICAL
    rows = repo.get_recovery_events(service=SERVICE_SURICATA)
    assert "NO_NEW_STATS" in rows[0]["error"]


def test_polls_every_restart_wait_until_new_stats():
    waits = []
    manager, _ = lab_recovery(schedule=[(12, 10)])
    inner = manager.sleep
    manager.sleep = lambda s: (waits.append(s), inner(s))
    manager.recover(DOWN)
    assert waits == [WAIT_SEC, WAIT_SEC, WAIT_SEC], "5s -> 10s -> 15s (stats ใหม่มาที่ 12s)"


def test_stats_without_uptime_cannot_prove_new_process():
    clock = LabClock(T_RESTART)
    monitor = HealthMonitor(RunningController(), 10, 3, clock=clock)
    clock.now = T_RESTART + timedelta(seconds=10)
    monitor.on_stats({"event_type": "stats", "stats": {}})
    assert monitor.new_stats_since(T_RESTART) is False


def test_normal_health_check_is_unchanged():
    """FR-12 ปกติ (ไม่มี since): stats สด < 30s = HEALTHY เหมือนเดิม"""
    clock = LabClock(T_RESTART)
    monitor = HealthMonitor(RunningController(), 10, 3, clock=clock)
    monitor.on_stats(stats(147))
    clock.now = T_RESTART + timedelta(seconds=9.6)
    assert monitor.check().state == HEALTHY
    # stats เดียวกันใช้ยืนยัน recovery ไม่ได้: process uptime 147s ไม่ได้เริ่มหลัง restart
    assert monitor.check(since=T_RESTART - timedelta(seconds=1)).state == DEGRADED


def test_new_process_stats_pass_recovery_check():
    clock = LabClock(T_RESTART + timedelta(seconds=12))
    monitor = HealthMonitor(RunningController(), 10, 3, clock=clock)
    monitor.on_stats(stats(10))
    status = monitor.check(since=T_RESTART)
    assert status.state == HEALTHY


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
