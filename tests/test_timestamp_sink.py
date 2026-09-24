"""
tests/test_timestamp_sink.py — FR-15 runtime sink: trace -> experiment_timestamps

    SecurityPipeline(trace_sink=ExperimentTimestampSink(repo, "T4", "3"))
        -> _emit(trace) -> sink(trace) -> 1 แถวต่อ trace ที่ correlation match

ขอบเขต (แยกจาก test_experiment_timestamps.py ซึ่งดู trace ของ pipeline):
ไฟล์นี้ดูว่า sink แปลง trace เป็นแถว FR-15 ถูกความหมายหรือไม่

สิ่งที่ล็อก
A  BLOCK verified          -> ครบ 5 จุด ค่าเท่ากับ trace ทุกตัว
B  ALERT / NO_AUTO_BLOCK   -> t_block_* = NULL
C  matched แต่ MONITOR     -> มีแถว (มี t_decision) t_block_* = NULL
D1 verify ล้ม              -> t_block_cmd มี, t_block_verified = NULL
D2 block ถูกระงับ          -> trace มี t_block_cmd แต่แถวเป็น NULL + suppressed=1
                              (t_block_cmd ของ FR-15 = คำสั่งที่ส่งไป pfSense จริง)
D3a sink บันทึกไม่สำเร็จ    -> engine ไม่ล้ม, log ERROR, ไม่มีแถว, ไม่สร้างเวลาใหม่
D3b exception ก่อน _emit() -> ไม่มีแถว (limitation ตาม decision 6a — ไม่แก้ pipeline)
E  identity                -> T1..T11 + run_id [A-Za-z0-9_-]{1,32} เท่านั้น
no-match (4a)              -> ไม่มีแถว
"""
import json
import logging
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import generate_test_events as gen                     # noqa: E402

from security_engine.correlation.engine import CorrelationEngine    # noqa: E402
from security_engine.enforcement.pfsense_enforcer import EnforcementError  # noqa: E402
from security_engine.experiment.timestamp_sink import (  # noqa: E402
    ExperimentIdentityError, ExperimentTimestampSink, validate_identity,
)
from security_engine.ingestion.eve_reader import iter_events  # noqa: E402
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager  # noqa: E402
from security_engine.lifecycle.block_store import BlockStore  # noqa: E402
from security_engine.pipeline import SecurityPipeline  # noqa: E402
from security_engine.policy.rule_engine import RuleEngine  # noqa: E402
from security_engine.policy.rules_config import load_rules  # noqa: E402
from security_engine.storage.repository import (  # noqa: E402
    AuditPersistenceError, AuditRepository,
)

T0 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
IP = "198.51.100.77"
ALLOWLISTED = "192.168.2.10"
FIELDS = ("t_event", "t_detection", "t_decision", "t_block_cmd", "t_block_verified")


class FakeResult:
    def __init__(self, action, ip, ok=True):
        self.action = action
        self.ip = ip
        self.command_ok = ok
        self.verified = ok
        self.status = "ENFORCED" if ok else "FAILED"

    @property
    def success(self):
        return self.command_ok and self.verified


class FakeEnforcer:
    """ไม่มี SSH/pfSense — add_ok=False = verify ล้ม, raises = โยน exception"""

    def __init__(self, add_ok=True, raises=None):
        self.add_ok = add_ok
        self.raises = raises
        self.added = []

    def add_block(self, ip):
        self.added.append(ip)
        if self.raises is not None:
            raise self.raises
        return FakeResult("add", ip, self.add_ok)

    def remove_block(self, ip):
        return FakeResult("remove", ip, True)

    def is_blocked(self, ip):
        return ip in self.added


def build_stack(tmp_path, *, enforcer=None, allowlist=None, test_id="T4", run_id="3"):
    """pipeline + lifecycle + repository จริง (DB เดียว) + sink — เหมือน run_phase4"""
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    sink = ExperimentTimestampSink(repo, test_id, run_id)
    mgr = BlockLifecycleManager(enforcer or FakeEnforcer(), BlockStore(db))
    pipe = SecurityPipeline(
        CorrelationEngine(window_seconds=10, min_events=5),
        RuleEngine(load_rules(), allowlist=allowlist or set()), mgr,
        lock=threading.Lock(), min_events=5, window_max=10.0,
        repository=repo, trace_sink=sink)
    return pipe, repo, sink


def eve(severity=1, offset=0.0, src=IP):
    ts = (T0 + timedelta(seconds=offset)).isoformat()
    return {"src_ip": src, "dest_ip": "192.0.2.10", "severity": severity,
            "signature": "ET TEST", "signature_id": 2001219,
            "event_type": "alert", "timestamp": ts, "received_at": ts}


def feed(pipe, count=5, severity=1, start=0.0, src=IP):
    trace = None
    for i in range(count):
        trace = pipe.process(eve(severity, offset=start + i * 0.5, src=src))
    return trace


def only_row(repo, test_id="T4"):
    rows = repo.get_experiment_timestamps(test_id)
    assert len(rows) == 1, rows
    return rows[0]


def assert_row_copies_trace(row, trace, *, except_fields=()):
    """ค่าเวลาในแถวต้องมาจาก trace เดียวกันทุกตัว — sink ไม่สร้างเวลาใหม่"""
    for field in FIELDS:
        if field not in except_fields:
            assert row[field] == trace[field], field


# ---------- A. BLOCK verified ----------
def test_block_verified_row_has_all_five_timestamps(tmp_path):
    pipe, repo, _ = build_stack(tmp_path)
    trace = feed(pipe)
    assert trace["decision"] == "BLOCK"

    row = only_row(repo)
    for field in FIELDS:
        assert row[field] is not None, field
    assert_row_copies_trace(row, trace)


def test_block_row_is_in_pipeline_order(tmp_path):
    pipe, repo, _ = build_stack(tmp_path)
    feed(pipe)
    row = only_row(repo)
    order = [datetime.fromisoformat(row[f]) for f in
             ("t_detection", "t_decision", "t_block_cmd", "t_block_verified")]
    assert order == sorted(order)


def test_row_identity_and_notes(tmp_path):
    pipe, repo, _ = build_stack(tmp_path, test_id="T4", run_id="3")
    feed(pipe)
    row = only_row(repo, "T4")
    assert row["test_id"] == "T4"
    assert row["notes"] == "run=3; mode=injection; decision=BLOCK; suppressed=0"


def test_sink_returns_row_id(tmp_path):
    pipe, repo, sink = build_stack(tmp_path)
    trace = feed(pipe, count=4)
    row_id = sink(dict(trace, correlation_matched=True, decision="BLOCK"))
    assert row_id == repo.get_experiment_timestamps("T4")[0]["id"]


# ---------- B. ALERT / NO_AUTO_BLOCK ----------
def test_alert_row_has_decision_but_no_block_timestamps(tmp_path):
    pipe, repo, _ = build_stack(tmp_path)
    trace = feed(pipe, severity=2)
    assert trace["decision"] == "ALERT"

    row = only_row(repo)
    assert row["t_decision"] is not None
    assert row["t_block_cmd"] is None
    assert row["t_block_verified"] is None
    assert_row_copies_trace(row, trace)
    assert "decision=ALERT" in row["notes"]


def test_no_auto_block_row_has_no_block_timestamps(tmp_path):
    enforcer = FakeEnforcer()
    pipe, repo, _ = build_stack(tmp_path, enforcer=enforcer, allowlist={ALLOWLISTED})
    trace = feed(pipe, src=ALLOWLISTED)
    assert trace["decision"] == "NO_AUTO_BLOCK"

    row = only_row(repo)
    assert row["t_block_cmd"] is None
    assert row["t_block_verified"] is None
    assert_row_copies_trace(row, trace)
    assert enforcer.added == []


# ---------- C. correlation match แต่ MONITOR ----------
def test_matched_monitor_still_writes_row(tmp_path):
    pipe, repo, _ = build_stack(tmp_path)
    trace = feed(pipe, severity=3)
    assert trace["correlation_matched"] is True
    assert trace["decision"] == "MONITOR"

    row = only_row(repo)
    assert row["t_decision"] is not None
    assert row["t_block_cmd"] is None
    assert row["t_block_verified"] is None
    assert "decision=MONITOR" in row["notes"]


# ---------- D1. verify ล้ม ----------
def test_failed_verify_keeps_command_but_not_verified(tmp_path):
    pipe, repo, _ = build_stack(tmp_path, enforcer=FakeEnforcer(add_ok=False))
    trace = feed(pipe)

    row = only_row(repo)
    assert row["t_block_cmd"] is not None
    assert row["t_block_verified"] is None
    assert_row_copies_trace(row, trace)
    assert "suppressed=0" in row["notes"]


# ---------- D2. block ถูกระงับ (duplicate ACTIVE) ----------
def test_suppressed_duplicate_block_has_null_command_in_row(tmp_path):
    """trace ตั้ง t_block_cmd ก่อนเข้า lifecycle.block() — ไม่ได้แปลว่าส่งคำสั่งจริง
    FR-15 ต้องสะท้อนคำสั่งที่ไป pfSense จริง -> แถวเป็น NULL"""
    enforcer = FakeEnforcer()
    pipe, repo, _ = build_stack(tmp_path, enforcer=enforcer)
    feed(pipe)                                   # pattern แรก -> BLOCK จริง
    trace = feed(pipe, start=20)                 # พ้น cooldown แต่ยัง ACTIVE

    assert trace["decision"] == "BLOCK"
    assert trace["t_block_cmd"] is not None
    assert trace["block_suppressed"] is True
    assert trace["duplicate_block"] is True
    assert enforcer.added == [IP]                # ยิง pfSense ครั้งเดียว

    rows = repo.get_experiment_timestamps("T4")
    assert len(rows) == 2
    first, row = rows
    assert "suppressed=0" in first["notes"]
    assert first["t_block_cmd"] is not None

    assert row["t_block_cmd"] is None
    assert "suppressed=1" in row["notes"]
    assert row["t_block_verified"] is None
    assert_row_copies_trace(row, trace, except_fields=("t_block_cmd",))


def test_suppressed_without_duplicate_also_nulls_command(tmp_path):
    """REMOVE_FAILED ก็ถูกระงับเช่นกัน — sink ดูที่ block_suppressed ไม่ใช่ duplicate_block"""
    repo = AuditRepository(tmp_path / "itis.db")
    sink = ExperimentTimestampSink(repo, "T6", "1")
    ts = T0.isoformat()
    sink({"correlation_matched": True, "decision": "BLOCK", "src_ip": IP,
          "t_event": ts, "t_detection": ts, "t_decision": ts,
          "t_block_cmd": ts, "t_block_verified": None,
          "duplicate_block": False, "block_suppressed": True})
    row = only_row(repo, "T6")
    assert row["t_block_cmd"] is None
    assert "suppressed=1" in row["notes"]


# ---------- D3a. sink บันทึกไม่สำเร็จ ----------
def test_sink_persistence_failure_does_not_crash_engine(tmp_path, monkeypatch, caplog):
    pipe, repo, sink = build_stack(tmp_path)

    def broken(*args, **kwargs):
        raise AuditPersistenceError("disk full")

    monkeypatch.setattr(repo, "save_experiment_timestamps", broken)
    with caplog.at_level(logging.ERROR,
                         logger="security_engine.experiment.timestamp_sink"):
        trace = feed(pipe)                       # ต้องไม่ raise

    assert trace["decision"] == "BLOCK"
    assert trace["t_block_verified"] is not None  # enforcement จริงไม่ถูกแก้
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and "experiment_timestamps" in errors[0].getMessage()
    assert "disk full" in errors[0].getMessage()

    monkeypatch.undo()
    assert repo.get_experiment_timestamps() == []


def test_sink_returns_none_on_persistence_failure(tmp_path, monkeypatch):
    repo = AuditRepository(tmp_path / "itis.db")
    sink = ExperimentTimestampSink(repo, "T4", "1")
    calls = []

    def broken(*args, **kwargs):
        calls.append(kwargs)
        raise AuditPersistenceError("locked")

    monkeypatch.setattr(repo, "save_experiment_timestamps", broken)
    ts = T0.isoformat()
    trace = {"correlation_matched": True, "decision": "ALERT", "src_ip": IP,
             "t_event": ts, "t_detection": ts, "t_decision": ts,
             "t_block_cmd": None, "t_block_verified": None}
    assert sink(trace) is None
    assert len(calls) == 1                       # ไม่ retry ด้วยเวลาใหม่
    assert calls[0]["t_decision"] == ts          # ค่าที่ส่งคือค่าจาก trace


# ---------- D3b. exception ก่อน _emit() -> ไม่มีแถว (limitation 6a) ----------
def test_enforcement_exception_before_emit_writes_no_row(tmp_path):
    """EnforcementError หลุดจาก lifecycle.block() ก่อน _emit() -> sink ไม่ถูกเรียก
    ข้อจำกัดที่ยอมรับ (6a): ไม่แก้ pipeline.py และไม่ประกอบแถวย้อนหลัง"""
    enforcer = FakeEnforcer(raises=EnforcementError("SSH timeout"))
    pipe, repo, _ = build_stack(tmp_path, enforcer=enforcer)
    feed(pipe, count=4)
    with pytest.raises(EnforcementError):
        pipe.process(eve(offset=2.0))
    assert repo.get_experiment_timestamps() == []


def test_audit_failure_before_emit_writes_no_row(tmp_path, monkeypatch):
    """_audit_enforcement() ล้มก่อน _emit() -> AuditPersistenceError ทะลุขึ้นไป
    (NFR-06 ของ pipeline) และไม่มีแถว FR-15 — ต่างจาก D3a ที่ sink ล้มเอง"""
    pipe, repo, _ = build_stack(tmp_path)

    def broken(*args, **kwargs):
        raise AuditPersistenceError("actions write failed")

    monkeypatch.setattr(repo, "save_enforcement_action", broken)
    feed(pipe, count=4)
    with pytest.raises(AuditPersistenceError):
        pipe.process(eve(offset=2.0))
    assert repo.get_experiment_timestamps() == []


# ---------- no-match (4a) ----------
def test_no_correlation_match_writes_no_row(tmp_path):
    pipe, repo, _ = build_stack(tmp_path)
    trace = feed(pipe, count=4)
    assert trace["correlation_matched"] is False
    assert repo.get_experiment_timestamps() == []


def test_sink_ignores_unmatched_trace_directly(tmp_path):
    repo = AuditRepository(tmp_path / "itis.db")
    sink = ExperimentTimestampSink(repo, "T2", "1")
    assert sink({"correlation_matched": False, "t_event": T0.isoformat()}) is None
    assert repo.get_experiment_timestamps() == []


# ---------- E. identity ----------
@pytest.mark.parametrize("test_id", ["T1", "T4", "T11"])
def test_valid_test_ids(test_id):
    assert validate_identity(test_id, "1") == (test_id, "1")


@pytest.mark.parametrize("test_id", ["T0", "T12", "t4", "A1", "", None, "T4 "])
def test_invalid_test_id_rejected(test_id):
    with pytest.raises(ExperimentIdentityError):
        validate_identity(test_id, "1")


@pytest.mark.parametrize("run_id", ["", None, "a b", "../x", "3;DROP", "x" * 33])
def test_invalid_run_id_rejected(run_id):
    with pytest.raises(ExperimentIdentityError):
        validate_identity("T4", run_id)


def test_run_id_int_is_normalized_to_str():
    assert validate_identity("T4", 3) == ("T4", "3")


def test_sink_rejects_bad_identity_at_construction(tmp_path):
    repo = AuditRepository(tmp_path / "itis.db")
    with pytest.raises(ExperimentIdentityError):
        ExperimentTimestampSink(repo, "T99", "1")


def test_identity_is_fixed_for_sink_lifetime(tmp_path):
    """I1: 1 process = 1 run — ทุกแถวของ sink ตัวเดียวกันมี identity เดียวกัน"""
    pipe, repo, _ = build_stack(tmp_path, test_id="T3", run_id="5")
    feed(pipe, severity=2)
    feed(pipe, severity=2, start=20)
    rows = repo.get_experiment_timestamps()
    assert len(rows) == 2
    assert {r["test_id"] for r in rows} == {"T3"}
    assert all(r["notes"].startswith("run=5;") for r in rows)


# ---------- end-to-end: generator -> ingestion -> pipeline -> sink ----------
def run_generated(tmp_path, test_id, variant=None):
    raw = [json.dumps(e) for e in gen.generate(test_id, variant=variant)]
    pipe, repo, _ = build_stack(tmp_path, test_id=test_id, run_id="1")
    for event in iter_events(iter(raw)):
        pipe.process(event)
    return repo.get_experiment_timestamps(test_id)


def test_generated_t4_writes_one_complete_row(tmp_path):
    rows = run_generated(tmp_path, "T4")
    assert len(rows) == 1
    for field in FIELDS:
        assert rows[0][field] is not None, field
    assert "decision=BLOCK" in rows[0]["notes"]


def test_generated_t3_writes_row_without_block(tmp_path):
    rows = run_generated(tmp_path, "T3")
    assert len(rows) == 1
    assert rows[0]["t_decision"] is not None
    assert rows[0]["t_block_cmd"] is None
    assert rows[0]["t_block_verified"] is None


@pytest.mark.parametrize("test_id,variant", [("T1", None), ("T2", None),
                                             ("T10", "a"), ("T10", "b")])
def test_generated_unmatched_scenarios_write_no_row(tmp_path, test_id, variant):
    assert run_generated(tmp_path, test_id, variant) == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
