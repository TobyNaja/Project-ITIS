"""
tests/test_run_experiment.py — Phase 12 Synthetic Runner (logic mode + retry, offline)

พิสูจน์:
  1. scenario T10/T3/T4/T5 นิยามถูก (event count + expected decision ตรง spec)
  2. รัน logic mode จริง (FakeEnforcer) -> decision ตรง expected + trial_status=SUCCESS
  3. ทุก trace ถูก tag input_mode="synthetic" (กันปนกับ real Suricata)
  4. retry behavior (EnforcementError): SUCCESS retry=0 / SUCCESS หลัง retry / FAILED
  5. FAILED trace ไม่มี latency fields (analyzer จะ exclude เอง)

ไม่แตะ pfSense / SSH — enforcer ที่โยน error เป็นตัวปลอมใน test
"""
import json
from pathlib import Path

import pytest

import run_experiment as rx
from security_engine.enforcement.pfsense_enforcer import EnforcementError


@pytest.fixture(autouse=True)
def _no_retry_delay(monkeypatch):
    # กัน test ช้าเพราะ retry delay 2 วิจริง
    monkeypatch.setattr(rx, "RETRY_DELAY_S", 0)


# ---- 1. scenario definitions ----
def test_scenarios_use_canonical_test_ids():
    """ป้าย A1–A4 ปลดระวางแล้ว (STEP 10) — canonical ID คือ T-number"""
    assert rx.SCENARIOS == ["T10", "T3", "T4", "T5"]
    assert not [s for s in rx.SCENARIOS if s.startswith("A")]


def test_legacy_labels_still_map_to_test_ids():
    """trace เก่าใช้ A1–A4 — ต้องแปลได้ แต่ไม่ใช่ชื่อหลักอีกต่อไป"""
    assert rx.LEGACY_LABELS == {"A1": "T10", "A2": "T3", "A3": "T4", "A4": "T5"}
    for legacy, canonical in rx.LEGACY_LABELS.items():
        old_events, old_expected = rx.scenario_events(legacy)
        new_events, new_expected = rx.scenario_events(canonical)
        # timestamp เป็น now() จึงเทียบรูปร่างของ scenario ไม่ใช่ตัวเวลา
        assert old_expected == new_expected
        assert [(e["src_ip"], e["dest_ip"], e["severity"]) for e in old_events] ==                [(e["src_ip"], e["dest_ip"], e["severity"]) for e in new_events]


def test_t10_below_min_events_none():
    events, expected = rx.scenario_events("T10")
    assert len(events) == 4
    assert expected is None


def test_t3_medium_alert():
    events, expected = rx.scenario_events("T3")
    assert len(events) == 5 and expected == "ALERT"
    assert {e["dest_ip"] for e in events} == {"a", "b", "c", "d", "e"}
    # RULE-002 ใช้ raw severity: MEDIUM = Suricata severity 2 (ไม่ใช่ risk_level)
    assert all(e["severity"] == 2 for e in events)


def test_t4_critical_block():
    events, expected = rx.scenario_events("T4")
    assert len(events) == 5 and expected == "BLOCK"
    assert {e["dest_ip"] for e in events} == {"x"}
    assert all(e["severity"] == 1 for e in events)


def test_t5_allowlisted_no_auto_block():
    events, expected = rx.scenario_events("T5")
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
    from security_engine.policy.rules_config import load_rules
    from security_engine.lifecycle.block_store import BlockStore
    from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
    from security_engine.pipeline import SecurityPipeline
    import threading

    def fake_build(mode, host, db_path):
        corr = CorrelationEngine(window_seconds=rx.WINDOW_MAX, min_events=rx.MIN_EVENTS)
        rule = RuleEngine(load_rules(), allowlist={rx.ALLOWLISTED_SRC})
        store = BlockStore(db_path)
        lifecycle = BlockLifecycleManager(enforcer, store)
        pipe = SecurityPipeline(corr, rule, lifecycle, lock=threading.Lock(),
                                min_events=rx.MIN_EVENTS, window_max=rx.WINDOW_MAX)
        return pipe, enforcer, lifecycle

    monkeypatch.setattr(rx, "build", fake_build)


def test_a3_success_first_try(tmp_path, monkeypatch):
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=0))
    trace, expected = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "T4", retries=2)
    assert trace["trial_status"] == "SUCCESS"
    assert trace["retry_count"] == 0
    assert trace["decision"] == "BLOCK"
    assert trace["enforcement_ok"] is True
    assert trace.get("t5_enforce_ok") is not None      # มี latency จริง


def test_a3_recovers_after_one_retry(tmp_path, monkeypatch):
    # ล้ม 1 ครั้งแรก แล้วสำเร็จ -> SUCCESS retry_count=1
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=1))
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "T4", retries=2)
    assert trace["trial_status"] == "SUCCESS"
    assert trace["retry_count"] == 1
    assert trace["enforcement_ok"] is True
    assert trace.get("t5_enforce_ok") is not None


def test_a3_fails_after_retries_exhausted(tmp_path, monkeypatch):
    # ล้มตลอด (มากกว่า retries+1) -> FAILED
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=99))
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "T4", retries=2)
    assert trace["trial_status"] == "FAILED"
    assert trace["retry_count"] == 2
    assert trace["enforcement_ok"] is False
    assert trace["error"] == "timed out after 10 seconds"


def test_failed_trace_has_no_latency(tmp_path, monkeypatch):
    # กฎเหล็ก: FAILED trial ห้ามมี latency fields -> analyzer exclude เอง ไม่ปนสถิติ
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=99))
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "T4", retries=2)
    for k in ("t0_received", "t5_enforce_ok", "detection_s", "enforcement_s", "end_to_end_s"):
        assert k not in trace, f"FAILED trace ต้องไม่มี {k}"


def test_failed_trace_does_not_claim_a_decision(tmp_path, monkeypatch):
    """FAILED = pipeline ไม่เคย emit trace -> ห้ามมี decision ที่ engine ไม่ได้ตัดสิน

    ความคาดหมายไปอยู่ช่อง expected_decision แยกต่างหาก เพื่อไม่ให้ถูกกรอกลง
    ช่อง decision ของ results CSV แทนผลจริง
    """
    _patch_build(monkeypatch, FlakyEnforcer(fail_times=99))
    trace, expected = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"),
                                   "T4", retries=2)
    assert trace["trial_status"] == "FAILED"
    assert trace["decision"] is None
    assert trace["expected_decision"] == expected == "BLOCK"


def test_non_block_scenario_never_retries(tmp_path, monkeypatch):
    # T3 (ALERT) ไม่เข้า enforcement -> enforcer ไม่ถูกเรียก -> ไม่ retry แม้ enforcer จะ flaky
    fe = FlakyEnforcer(fail_times=99)
    _patch_build(monkeypatch, fe)
    trace, _ = rx.run_trial("enforcement", "h", str(tmp_path / "x.db"), "T3", retries=2)
    assert trace["trial_status"] == "SUCCESS"
    assert trace["decision"] == "ALERT"
    assert fe.calls == 0                # add_block ไม่เคยถูกเรียก


# ---- 6. FR-15: experiment_timestamps ต่อ trial (STEP 10) ----
def test_record_timestamps_writes_real_pipeline_times(tmp_path):
    from security_engine.storage.repository import AuditRepository

    repo = AuditRepository(str(tmp_path / "ts.db"))
    trace = {"t_event": "2026-01-01T12:00:00+00:00",
             "t_detection": "2026-01-01T12:00:00.100000+00:00",
             "t_decision": "2026-01-01T12:00:00.200000+00:00",
             "t_block_cmd": "2026-01-01T12:00:00.250000+00:00",
             "t_block_verified": "2026-01-01T12:00:00.900000+00:00",
             "input_mode": "synthetic", "trial_status": "SUCCESS"}
    rx.record_timestamps(repo, "T4", 3, trace)

    row = repo.get_experiment_timestamps("T4")[0]
    assert row["t_event"] == trace["t_event"]
    assert row["t_block_verified"] == trace["t_block_verified"]
    assert "run=3" in row["notes"], "run_id อยู่ใน notes (schema ไม่มีคอลัมน์ repetition)"


def test_record_timestamps_keeps_missing_points_null(tmp_path):
    from security_engine.storage.repository import AuditRepository

    repo = AuditRepository(str(tmp_path / "ts.db"))
    rx.record_timestamps(repo, "T3", 1, {"t_event": "2026-01-01T12:00:00+00:00",
                                         "t_decision": "2026-01-01T12:00:00.2+00:00"})
    row = repo.get_experiment_timestamps("T3")[0]
    assert row["t_block_cmd"] is None and row["t_block_verified"] is None


def test_record_timestamps_survives_db_failure(tmp_path, capsys):
    """audit ล้ม != trial ล้ม (NFR-06)"""
    from security_engine.storage.repository import AuditPersistenceError

    class BrokenRepo:
        def save_experiment_timestamps(self, *a, **k):
            raise AuditPersistenceError("disk full")

    assert rx.record_timestamps(BrokenRepo(), "T4", 1, {"t_event": "x"}) is None
    assert "experiment_timestamps" in capsys.readouterr().out


def test_record_timestamps_without_repository_is_noop():
    assert rx.record_timestamps(None, "T4", 1, {"t_event": "x"}) is None


def test_run_persists_one_row_per_trial(tmp_path, monkeypatch):
    from security_engine.storage.repository import AuditRepository

    _patch_build(monkeypatch, FlakyEnforcer(fail_times=0))   # สำเร็จทุกครั้ง
    repo = AuditRepository(str(tmp_path / "run.db"))
    rx.run("logic", str(tmp_path / "t.jsonl"), 2, None, str(tmp_path / "run.db"),
           block_duration=10, retries=0, test_ids=["T4"], repository=repo)

    rows = repo.get_experiment_timestamps("T4")
    assert len(rows) == 2
    assert [r["notes"].split(";")[0] for r in rows] == ["run=1", "run=2"]
    assert all(r["t_decision"] for r in rows), "ต้องเป็นเวลาที่ pipeline บันทึกจริง"


# ---- 7. NFR-07: ไม่มีค่า lab ฝังในโค้ด ----
def test_no_lab_host_hardcoded_in_runner():
    source = Path(rx.__file__).read_text(encoding="utf-8")
    assert "192.168." not in source
    assert "admin@" not in source


def test_enforcement_mode_requires_host_from_env(monkeypatch, tmp_path):
    from security_engine.settings import ConfigError

    monkeypatch.delenv(rx.ENV_PFSENSE_HOST, raising=False)
    monkeypatch.setattr("sys.argv", ["run_experiment.py", "--mode", "enforcement",
                                     "--out", str(tmp_path / "x.jsonl")])
    monkeypatch.setattr(rx, "run", lambda *a, **k: pytest.fail(
        "ต้องพังก่อนเริ่มรัน เมื่อไม่มี ITIS_PFSENSE_HOST"))
    with pytest.raises(ConfigError):
        rx.main()


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))