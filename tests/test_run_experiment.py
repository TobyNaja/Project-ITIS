"""
tests/test_run_experiment.py — Phase 12 Synthetic Runner (logic mode + retry, offline)

พิสูจน์:
  1. scenario A1–A4 นิยามถูก (event count + expected decision ตรง spec)
  2. รัน logic mode จริง (FakeEnforcer) -> decision ตรง expected + trial_status=SUCCESS
  3. ทุก trace ถูก tag input_mode="synthetic" (กันปนกับ real Suricata)
  4. retry behavior (EnforcementError): SUCCESS retry=0 / SUCCESS หลัง retry / FAILED
  5. FAILED trace ไม่มี latency fields (analyzer จะ exclude เอง)

ไม่แตะ pfSense / SSH — enforcer ที่โยน error เป็นตัวปลอมใน test
"""
import json

import pytest

import run_experiment as rx
from security_engine.enforcement.pfsense_enforcer import EnforcementError


@pytest.fixture(autouse=True)
def _no_retry_delay(monkeypatch):
    # กัน test ช้าเพราะ retry delay 2 วิจริง
    monkeypatch.setattr(rx, "RETRY_DELAY_S", 0)


# ---- 1. scenario definitions ----
def test_scenarios_are_four():
    assert rx.SCENARIOS == ["A1", "A2", "A3", "A4"]


def test_a1_below_min_events_none():
    events, expected = rx.scenario_events("A1")
    assert len(events) == 4
    assert expected is None


def test_a2_medium_alert():
    events, expected = rx.scenario_events("A2")
    assert len(events) == 5 and expected == "ALERT"
    assert {e["dest_ip"] for e in events} == {"a", "b", "c", "d", "e"}
    assert all(e["severity"] == 3 for e in events)


def test_a3_critical_block():
    events, expected = rx.scenario_events("A3")
    assert len(events) == 5 and expected == "BLOCK"
    assert {e["dest_ip"] for e in events} == {"x"}
    assert all(e["severity"] == 1 for e in events)


def test_a4_allowlisted_no_auto_block():
    events, expected = rx.scenario_events("A4")
    assert expected == "NO_AUTO_BLOCK"
    assert all(e["src_ip"] == rx.ALLOWLISTED_SRC for e in events)


def test_unknown_scenario_raises():
    with pytest.raises(ValueError):
        rx.scenario_events("A9")


def test_no_monitor_scenario_by_design():
    expecteds = {rx.scenario_events(s)[1] for s in rx.SCENARIOS}
    assert "MONITOR" not in expecteds


# ---- 2+3. logic mode end-to-end ----
def test_logic_mode_all_decisions_match(tmp_path):
    out = tmp_path / "traces_logic.jsonl"
    results = rx.run("logic", str(out), trials=2, host="unused",
                     db_path=str(tmp_path / "exp.db"), block_duration=10, retries=2)
    mismatches = [r for r in results if not r[6]]
    assert not mismatches, f"decision mismatches: {mismatches}"
    assert len(results) == 8       # 4 scenario x 2 trial


def test_logic_mode_traces_tagged_synthetic(tmp_path):
    out = tmp_path / "traces_logic.jsonl"
    rx.run("logic", str(out), trials=1, host="unused",
           db_path=str(tmp_path / "exp.db"), block_duration=10, retries=2)
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines
    assert all(r.get("input_mode") == "synthetic" for r in lines)


def test_logic_mode_all_success_status(tmp_path):
    # logic mode (FakeEnforcer) ไม่มีทาง fail -> ทุก trace SUCCESS retry=0
    out = tmp_path / "traces_logic.jsonl"
    rx.run("logic", str(out), trials=1, host="unused",
           db_path=str(tmp_path / "exp.db"), block_duration=10, retries=2)
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert all(r["trial_status"] == "SUCCESS" for r in lines)
    assert all(r["retry_count"] == 0 for r in lines)


def test_fake_enforcer_never_touches_network():
    fe = rx.FakeEnforcer()
    assert fe.add_block("1.2.3.4").success is True
    assert fe.remove_block("1.2.3.4").success is True
    assert fe.is_blocked("1.2.3.4") is False
    assert fe.get_blocked_ips() == set()


# ---- 4+5. retry / failure behavior (enforcer ปลอมที่โยน error) ----
class FlakyEnforcer:
    """add_block ล้ม N ครั้งแรกด้วย EnforcementError แล้วค่อยสำเร็จ
    ใช้จำลอง SSH timeout ชั่วคราวของ pfSense"""
    def __init__(self, fail_times):
        self.fail_times = fail_times
        self.calls = 0

    def add_block(self, ip):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise EnforcementError("timed out after 10 seconds")
        return rx.FakeResult(True)

    def remove_block(self, ip): return rx.FakeResult(True)
    def is_blocked(self, ip): return False
    def get_blocked_ips(self): return set()


def _patch_build(monkeypatch, enforcer):
    """บังคับ build() ให้ใช้ enforcer ที่กำหนด (BlockLifecycleManager จริง)"""
    from security_engine.correlation.engine import CorrelationEngine
    from security_engine.policy.rule_engine import RuleEngine
    from security_engine.lifecycle.block_store import BlockStore
    from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
    from security_engine.pipeline import SecurityPipeline
    import threading

    def fake_build(mode, host, db_path):
        corr = CorrelationEngine(window_seconds=rx.WINDOW_MAX, min_events=rx.MIN_EVENTS)
        rule = RuleEngine(allowlist={rx.ALLOWLISTED_SRC}, min_events=rx.MIN_EVENTS,
                          max_window=rx.WINDOW_MAX)
        store = BlockStore(db_path)
        lifecycle = BlockLifecycleManager(enforcer, store)
        pipe = SecurityPipeline(corr, rule, lifecycle, lock=threading.Lock(),
                                min_events=rx.MIN_EVENTS, window_max=rx.WINDOW_MAX)
        return pipe, enforcer, lifecycle

    monkeypatch.setattr(rx, "build", fake_build)


def test_a3_success_first_try(tmp_path, monkeypatch):
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=0))
    trace, expected = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "A3", retries=2)
    assert trace["trial_status"] == "SUCCESS"
    assert trace["retry_count"] == 0
    assert trace["decision"] == "BLOCK"
    assert trace["enforcement_ok"] is True
    assert trace.get("t5_enforce_ok") is not None      # มี latency จริง


def test_a3_recovers_after_one_retry(tmp_path, monkeypatch):
    # ล้ม 1 ครั้งแรก แล้วสำเร็จ -> SUCCESS retry_count=1
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=1))
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "A3", retries=2)
    assert trace["trial_status"] == "SUCCESS"
    assert trace["retry_count"] == 1
    assert trace["enforcement_ok"] is True
    assert trace.get("t5_enforce_ok") is not None


def test_a3_fails_after_retries_exhausted(tmp_path, monkeypatch):
    # ล้มตลอด (มากกว่า retries+1) -> FAILED
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=99))
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "A3", retries=2)
    assert trace["trial_status"] == "FAILED"
    assert trace["retry_count"] == 2
    assert trace["enforcement_ok"] is False
    assert trace["error"] == "timed out after 10 seconds"


def test_failed_trace_has_no_latency(tmp_path, monkeypatch):
    # กฎเหล็ก: FAILED trial ห้ามมี latency fields -> analyzer exclude เอง ไม่ปนสถิติ
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=99))
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "A3", retries=2)
    for k in ("t0_received", "t5_enforce_ok", "detection_s", "enforcement_s", "end_to_end_s"):
        assert k not in trace, f"FAILED trace ต้องไม่มี {k}"


def test_non_block_scenario_never_retries(tmp_path, monkeypatch):
    # A2 (ALERT) ไม่เข้า enforcement -> enforcer ไม่ถูกเรียก -> ไม่ retry แม้ enforcer จะ flaky
    fe = FlakyEnforcer(fail_times=99)
    _patch_build(monkeypatch, fe)
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "A2", retries=2)
    assert trace["trial_status"] == "SUCCESS"
    assert trace["decision"] == "ALERT"
    assert fe.calls == 0                # add_block ไม่เคยถูกเรียก


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))