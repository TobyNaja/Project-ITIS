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

import pytest

from security_engine.health.monitor import (
    CRITICAL,
    DEGRADED,
    HEALTHY,
    REASON_EVE_STALE,
    REASON_PROCESS_DOWN,
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
    """check() คืน HealthStatus ตามสคริปต์ (ค่าสุดท้ายใช้ซ้ำ)"""

    def __init__(self, statuses=None):
        self.statuses = list(statuses or [RECOVERED])
        self.calls = 0

    def check(self):
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


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
