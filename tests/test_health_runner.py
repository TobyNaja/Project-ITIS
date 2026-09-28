"""
tests/test_health_runner.py — STEP 9B: health loop + wiring (FR-12/FR-13, NFR-02)

สองเรื่องที่ test ชุดนี้พิสูจน์

1. HealthRunner (thread)
   - เรียก monitor.check() ทุก check_interval_sec
   - DEGRADED -> ส่งต่อ RecoveryManager
   - exception ใน tick ต้องไม่ฆ่า thread และไม่ยุ่งกับ event pipeline
   - CRITICAL แล้วหยุดสั่ง restart ซ้ำ (ดู CRITICAL_IS_LATCHED) จนกว่าจะกลับมา HEALTHY
   - stop() ปลุก thread ทันที ไม่ต้องรอครบ interval

2. run_phase4 wiring
   - on_stats ของ monitor ถูกต่อเข้า stream_events จริง
   - health runner start/stop พร้อม lifecycle runner
   - health thread ล้ม ไม่ทำให้ loop ของ event หยุด
"""
import threading
import time

import pytest

import run_phase4
from security_engine.health.monitor import (
    CRITICAL,
    DEGRADED,
    HEALTHY,
    REASON_EVE_STALE,
    REASON_PROCESS_DOWN,
    HealthStatus,
)
from security_engine.health.recovery import RecoveryOutcome
from security_engine.health.runner import HealthRunner

DOWN = HealthStatus(state=DEGRADED, reasons=(REASON_PROCESS_DOWN,),
                    process_running=False, stats_age_sec=99.0)
STALE = HealthStatus(state=DEGRADED, reasons=(REASON_EVE_STALE,),
                     process_running=True, stats_age_sec=99.0)
OK = HealthStatus(state=HEALTHY, process_running=True, stats_age_sec=1.0)


class FakeMonitor:
    def __init__(self, statuses=None):
        self.statuses = list(statuses or [OK])
        self.calls = 0

    def check(self):
        self.calls += 1
        return self.statuses[min(self.calls - 1, len(self.statuses) - 1)]


class FakeRecovery:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [RecoveryOutcome(state=HEALTHY, attempts=1)])
        self.calls = []

    def recover(self, status):
        self.calls.append(status)
        return self.outcomes[min(len(self.calls) - 1, len(self.outcomes) - 1)]


# ---- 1. tick: HEALTHY ไม่ต้องกู้ ----
def test_healthy_tick_does_not_call_recovery():
    recovery = FakeRecovery()
    runner = HealthRunner(FakeMonitor([OK]), recovery)
    status = runner.tick()
    assert status.state == HEALTHY
    assert runner.state == HEALTHY
    assert recovery.calls == []


# ---- 2. tick: DEGRADED -> เรียก recovery พร้อมสถานะจริง ----
def test_degraded_tick_triggers_recovery():
    recovery = FakeRecovery()
    runner = HealthRunner(FakeMonitor([DOWN]), recovery)
    runner.tick()
    assert recovery.calls == [DOWN], "ต้องส่ง HealthStatus ตัวจริงเข้า recovery"
    assert runner.state == HEALTHY, "กู้สำเร็จ -> กลับมา HEALTHY"
    assert runner.last_outcome.attempts == 1


def test_runner_state_follows_recovery_outcome():
    recovery = FakeRecovery([RecoveryOutcome(state=CRITICAL, attempts=3,
                                             failure_reason=REASON_PROCESS_DOWN)])
    runner = HealthRunner(FakeMonitor([DOWN]), recovery)
    runner.tick()
    assert runner.state == CRITICAL


def test_runner_without_recovery_only_reports():
    runner = HealthRunner(FakeMonitor([DOWN]), recovery=None)
    assert runner.tick().state == DEGRADED
    assert runner.state == DEGRADED


# ---- 3. CRITICAL ไม่วน restart ไม่รู้จบ ----
def test_critical_stops_further_restart_attempts(caplog):
    """FR-13: 3 ครั้งคือเพดาน "ต่อเหตุการณ์" ไม่ใช่ "ต่อรอบตรวจทุก 15 วิ" """
    recovery = FakeRecovery([RecoveryOutcome(state=CRITICAL, attempts=3)])
    runner = HealthRunner(FakeMonitor([DOWN]), recovery)
    with caplog.at_level("ERROR"):
        for _ in range(5):
            runner.tick()
    assert len(recovery.calls) == 1, "เข้า CRITICAL แล้วต้องไม่สั่ง restart ซ้ำทุกรอบ"
    assert runner.state == CRITICAL


def test_health_returning_clears_critical_latch(caplog):
    recovery = FakeRecovery([RecoveryOutcome(state=CRITICAL, attempts=3),
                             RecoveryOutcome(state=HEALTHY, attempts=1)])
    monitor = FakeMonitor([DOWN, OK, DOWN])      # เสีย -> หายเอง -> เสียใหม่
    runner = HealthRunner(monitor, recovery)
    with caplog.at_level("WARNING"):
        runner.tick()                            # CRITICAL
        assert runner.state == CRITICAL
        runner.tick()                            # กลับมาปกติเอง -> ปลด latch
        assert runner.state == HEALTHY
        runner.tick()                            # เหตุการณ์ใหม่ -> กู้ได้อีกครั้ง
    assert len(recovery.calls) == 2
    assert runner.state == HEALTHY


# ---- 4. NFR-02: error ใน tick ต้องไม่ฆ่า thread ----
class ExplodingMonitor:
    def __init__(self):
        self.calls = 0

    def check(self):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("ssh หลุดกลางทาง")
        return OK


def test_tick_error_is_logged_and_loop_continues(caplog):
    errors = []
    runner = HealthRunner(ExplodingMonitor(), FakeRecovery(), interval=0.01,
                          on_error=errors.append)
    with caplog.at_level("ERROR"):
        runner.start()
        deadline = time.time() + 2
        while runner.monitor.calls < 3 and time.time() < deadline:
            time.sleep(0.01)
        runner.stop()
    assert errors and isinstance(errors[0], RuntimeError)
    assert runner.monitor.calls >= 3, "error รอบแรกต้องไม่ทำให้ thread ตาย"
    assert any("health check" in r.getMessage() for r in caplog.records)


# ---- 5. thread lifecycle ----
def test_start_and_stop_thread():
    runner = HealthRunner(FakeMonitor([OK]), FakeRecovery(), interval=0.01)
    runner.start()
    assert runner.is_running() is True
    runner.stop()
    assert runner.is_running() is False


def test_start_twice_does_not_spawn_second_thread():
    runner = HealthRunner(FakeMonitor([OK]), FakeRecovery(), interval=0.05)
    before = threading.active_count()
    runner.start()
    runner.start()
    try:
        assert threading.active_count() == before + 1
    finally:
        runner.stop()


def test_stop_wakes_thread_immediately():
    """ใช้ Event.wait ไม่ใช่ sleep -> ปิดได้เร็วแม้ interval ยาว"""
    runner = HealthRunner(FakeMonitor([OK]), FakeRecovery(), interval=30)
    runner.start()
    started = time.time()
    runner.stop(timeout=5)
    assert time.time() - started < 2, "ต้องไม่รอครบ 30 วินาที"
    assert runner.is_running() is False


def test_runner_checks_repeatedly():
    monitor = FakeMonitor([OK])
    runner = HealthRunner(monitor, FakeRecovery(), interval=0.01)
    runner.start()
    deadline = time.time() + 2
    while monitor.calls < 3 and time.time() < deadline:
        time.sleep(0.01)
    runner.stop()
    assert monitor.calls >= 3


# ---- 6. build_health(): ค่ามาจาก config ทั้งหมด ----
@pytest.fixture
def settings():
    from security_engine.settings import load_settings
    return load_settings()


def test_build_health_uses_config_values(settings):
    monitor, health_runner = build = run_phase4.build_health(
        settings, host="admin@198.51.100.10")
    assert monitor.stats_interval_sec == settings.health.stats_interval_sec
    assert monitor.stats_freshness_multiplier == \
        settings.health.stats_freshness_multiplier
    assert monitor.stats_freshness_sec == settings.health.stats_freshness_sec
    assert health_runner.interval == settings.health.check_interval_sec
    assert health_runner.recovery.max_attempts == settings.recovery.max_attempts
    assert health_runner.recovery.restart_wait_sec == settings.health.restart_wait_sec
    assert len(build) == 2


def test_build_health_shares_controller_between_monitor_and_recovery(settings):
    monitor, health_runner = run_phase4.build_health(settings, host="h")
    assert health_runner.recovery.controller is monitor.controller
    assert health_runner.recovery.monitor is monitor


def test_build_health_takes_restart_command_from_config(settings):
    monitor, _ = run_phase4.build_health(settings, host="h")
    assert monitor.controller.restart_command == settings.health.restart_command


def test_build_health_accepts_injected_controller(settings):
    class FakeController:
        def is_running(self):
            return True

    controller = FakeController()
    monitor, health_runner = run_phase4.build_health(
        settings, host="h", controller=controller)
    assert monitor.controller is controller
    assert health_runner.recovery.controller is controller


def test_build_health_passes_repository_to_recovery(settings):
    repo = object()
    _, health_runner = run_phase4.build_health(settings, host="h", repository=repo)
    assert health_runner.recovery.repository is repo


# ---- 7. run(): health runner ถูก start/stop คู่กับ lifecycle runner ----
class FakeRunner:
    def __init__(self, lifecycle=None, fail_on_stop=False):
        self.lifecycle = lifecycle or FakeLifecycle()
        self.events = []
        self.fail_on_stop = fail_on_stop

    def start(self):
        self.events.append("start")

    def stop(self):
        self.events.append("stop")
        if self.fail_on_stop:
            raise RuntimeError("stop ล้ม")


class FakeLifecycle:
    def __init__(self):
        self.reconciled = 0

    def reconcile(self):
        self.reconciled += 1


class FakePipeline:
    def __init__(self):
        self.processed = []

    def process(self, event):
        self.processed.append(event)
        return {"src_ip": event.get("src_ip"), "correlation_matched": False,
                "decision": "MONITOR"}


EVENTS = [{"src_ip": "198.51.100.5"}, {"src_ip": "198.51.100.6"}]


def test_run_starts_and_stops_health_runner():
    pipeline, runner, health = FakePipeline(), FakeRunner(), FakeRunner()
    run_phase4.run(pipeline, runner, iter(EVENTS), health_runner=health)
    assert health.events == ["start", "stop"]
    assert runner.events == ["start", "stop"]
    assert pipeline.processed == EVENTS


def test_run_without_health_runner_still_works():
    pipeline, runner = FakePipeline(), FakeRunner()
    run_phase4.run(pipeline, runner, iter(EVENTS))
    assert pipeline.processed == EVENTS


def test_health_runner_is_stopped_even_if_lifecycle_stop_fails():
    pipeline = FakePipeline()
    runner = FakeRunner(fail_on_stop=True)
    health = FakeRunner()
    with pytest.raises(RuntimeError):
        run_phase4.run(pipeline, runner, iter(EVENTS), health_runner=health)
    assert health.events == ["start", "stop"], "health thread ต้องไม่ค้างทิ้งไว้"


def test_health_runner_starts_after_reconcile():
    """reconcile (FR-10) ต้องเสร็จก่อน ไม่ให้ health ไปสั่ง restart ระหว่างกู้ state"""
    order = []
    lifecycle = FakeLifecycle()
    runner = FakeRunner(lifecycle=lifecycle)
    runner.start = lambda: order.append("lifecycle-start")
    runner.stop = lambda: order.append("lifecycle-stop")
    lifecycle.reconcile = lambda: order.append("reconcile")
    health = FakeRunner()
    health.start = lambda: order.append("health-start")
    health.stop = lambda: order.append("health-stop")

    run_phase4.run(FakePipeline(), runner, iter(()), health_runner=health)
    assert order == ["reconcile", "lifecycle-start", "health-start",
                     "lifecycle-stop", "health-stop"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
