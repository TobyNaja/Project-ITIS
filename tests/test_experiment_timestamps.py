"""
tests/test_experiment_timestamps.py — STEP 10A: FR-15 timing evidence (M1–M4)

    t_event ──M1──> t_detection ──M2──> t_decision ──M3──> t_block_verified
       └────────────────────── M4 ─────────────────────────────┘

สิ่งที่ test ชุดนี้กันไว้
1. จุดเวลาต้องถูกเก็บ "ตอนเหตุการณ์เกิดใน pipeline" ไม่ใช่เวลาที่ script เขียนทีหลัง
2. จุดเวลาที่ยังไม่เกิด ต้องเป็น NULL ไม่ใช่ now() (หลักฐานปลอม)
3. ทุกค่าเป็น UTC ISO-8601 (NFR-04)
4. ไม่แตะ schema — ใช้ตาราง experiment_timestamps ที่มีตั้งแต่ STEP 4
"""
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.correlation.engine import CorrelationEngine
from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import RuleEngine
from security_engine.policy.rules_config import load_rules
from security_engine.storage.repository import AuditRepository
from security_engine.storage.schema import TABLES

TEST_SRC = "198.51.100.77"
ALLOWLISTED_SRC = "203.0.113.9"


@pytest.fixture
def repo(tmp_path):
    return AuditRepository(str(tmp_path / "exp.db"))


# ---- 1. repository API ----
def test_save_and_read_back_full_row(repo):
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    row_id = repo.save_experiment_timestamps(
        "T4",
        t_event=base,
        t_detection=base + timedelta(milliseconds=120),
        t_decision=base + timedelta(milliseconds=180),
        t_block_cmd=base + timedelta(milliseconds=200),
        t_block_verified=base + timedelta(milliseconds=950),
        notes="run=1")
    assert row_id > 0

    rows = repo.get_experiment_timestamps("T4")
    assert len(rows) == 1
    row = rows[0]
    assert row["test_id"] == "T4"
    assert row["notes"] == "run=1"
    assert row["t_event"].startswith("2026-01-01T12:00:00")
    assert row["t_block_verified"].startswith("2026-01-01T12:00:00.950")


def test_missing_timestamps_stay_null(repo):
    """scenario ที่ไม่ block: t_block_* ต้องเป็น NULL ไม่ใช่เวลาปัจจุบัน"""
    repo.save_experiment_timestamps("T1", t_event=datetime.now(timezone.utc),
                                    t_detection=datetime.now(timezone.utc))
    row = repo.get_experiment_timestamps("T1")[0]
    assert row["t_decision"] is None
    assert row["t_block_cmd"] is None
    assert row["t_block_verified"] is None


def test_timestamps_are_utc_iso(repo):
    """เวลาที่ส่งมาเป็น local tz ต้องถูกแปลงเป็น UTC (NFR-04)"""
    local = datetime(2026, 1, 1, 19, 0, 0,
                     tzinfo=timezone(timedelta(hours=7)))      # 12:00Z
    repo.save_experiment_timestamps("T4", t_event=local)
    stored = repo.get_experiment_timestamps("T4")[0]["t_event"]
    assert "+00:00" in stored
    assert stored.startswith("2026-01-01T12:00:00")


def test_get_all_and_filter_by_test_id(repo):
    for test_id in ("T1", "T4", "T4"):
        repo.save_experiment_timestamps(test_id, t_event=datetime.now(timezone.utc))
    assert len(repo.get_experiment_timestamps()) == 3
    assert len(repo.get_experiment_timestamps("T4")) == 2
    assert repo.get_experiment_timestamps("T9") == []


def test_repetitions_are_separate_rows(repo):
    """T1–T10 × 5 repetitions -> 5 แถว แยกกันด้วย notes (schema ไม่มี run_id)"""
    for run in range(1, 6):
        repo.save_experiment_timestamps("T4", t_event=datetime.now(timezone.utc),
                                        notes=f"run={run}")
    rows = repo.get_experiment_timestamps("T4")
    assert [r["notes"] for r in rows] == [f"run={n}" for n in range(1, 6)]


def test_schema_unchanged(repo):
    """STEP 10 ห้ามเพิ่ม/แก้ตาราง — ต้องเป็น 8 ตารางเดิมของ §3.4"""
    with sqlite3.connect(repo.db_path) as conn:
        columns = [r[1] for r in conn.execute(
            "PRAGMA table_info(experiment_timestamps)")]
    assert columns == ["id", "test_id", "t_event", "t_detection", "t_decision",
                       "t_block_cmd", "t_block_verified", "notes"]
    assert len(TABLES) == 8


# ---- 2. pipeline บันทึกจุดเวลาจริงตอนเหตุการณ์เกิด ----
def build_pipeline(repository=None, allowlist=None):
    correlator = CorrelationEngine(window_seconds=10.0, min_events=5)
    rule_engine = RuleEngine(load_rules(), allowlist=allowlist or set())
    return SecurityPipeline(correlator, rule_engine, FakeLifecycle(),
                            lock=threading.Lock(), min_events=5, window_max=10.0,
                            repository=repository)


class FakeResult:
    def __init__(self, ok=True):
        self.success = ok
        self.command_ok = ok
        self.verified = ok
        self.status = "ENFORCED" if ok else "FAILED"
        self.action = "add"             # enforcer contract: add -> actions.BLOCK
        self.ip = TEST_SRC
        self.error = None
        self.duplicate = False
        self.suppressed = False


class FakeEnforcer:
    """enforcer ที่ "สำเร็จเสมอ" — ไม่มี SSH/pfSense ใน unit test"""

    def __init__(self):
        self.added = []

    def add_block(self, ip):
        self.added.append(ip)
        result = FakeResult(True)
        result.ip = ip
        return result

    def remove_block(self, ip):
        result = FakeResult(True)
        result.action = "remove"
        result.ip = ip
        return result

    def is_blocked(self, ip):
        return ip in self.added

    def get_blocked_ips(self):
        return set(self.added)


class FakeLifecycle:
    def __init__(self, ok=True):
        self.ok = ok
        self.blocked = []

    def block(self, decision):
        self.blocked.append(decision.src_ip)
        return FakeResult(self.ok)


def events(src, severity, count=5, dest_prefix="203.0.113."):
    now = datetime.now(timezone.utc)
    return [{"src_ip": src, "dest_ip": f"{dest_prefix}{i}", "severity": severity,
             "timestamp": now, "received_at": now,
             "signature": "TEST", "signature_id": 1000 + i}
            for i in range(count)]


def feed(pipeline, evs):
    trace = None
    for event in evs:
        trace = pipeline.process(event)
    return trace


def test_trace_carries_wall_clock_timestamps_for_block():
    trace = feed(build_pipeline(), events(TEST_SRC, 1))
    assert trace["decision"] == "BLOCK"
    for field in ("t_event", "t_detection", "t_decision", "t_block_cmd",
                  "t_block_verified"):
        assert trace[field] is not None, f"{field} ต้องถูกบันทึก"
        datetime.fromisoformat(trace[field])          # parse ได้ = ISO ถูกต้อง


def test_timestamps_are_monotonic_in_pipeline_order():
    trace = feed(build_pipeline(), events(TEST_SRC, 1))
    order = [datetime.fromisoformat(trace[f]) for f in
             ("t_detection", "t_decision", "t_block_cmd", "t_block_verified")]
    assert order == sorted(order), "ลำดับเวลาต้องตรงกับลำดับขั้นตอนจริง"


def test_wall_clock_timestamps_are_utc():
    trace = feed(build_pipeline(), events(TEST_SRC, 1))
    assert datetime.fromisoformat(trace["t_decision"]).utcoffset() == timedelta(0)


def test_t_event_comes_from_suricata_not_from_now():
    """t_event ต้องเป็นเวลาของ event ไม่ใช่เวลาที่ pipeline ประมวลผล"""
    evs = events(TEST_SRC, 1)
    event_time = evs[-1]["timestamp"]
    trace = feed(build_pipeline(), evs)
    assert datetime.fromisoformat(trace["t_event"]) == event_time


def test_monitor_scenario_has_no_decision_or_block_timestamps():
    """T1/T2: correlation ไม่ match -> ไม่มี t_decision/t_block_* (ต้องไม่ปลอมค่า)"""
    trace = feed(build_pipeline(), events(TEST_SRC, 1, count=4))
    assert trace["correlation_matched"] is False
    assert trace["t_decision"] is None
    assert trace["t_block_cmd"] is None
    assert trace["t_block_verified"] is None
    assert trace["t_detection"] is not None


def test_alert_scenario_has_decision_but_no_block_timestamps():
    """T3: ALERT -> มี t_decision แต่ไม่มี t_block_* (ไม่มีคำสั่งไป pfSense)"""
    trace = feed(build_pipeline(), events(TEST_SRC, 2))
    assert trace["decision"] == "ALERT"
    assert trace["t_decision"] is not None
    assert trace["t_block_cmd"] is None
    assert trace["t_block_verified"] is None


def test_allowlisted_scenario_has_no_block_timestamps():
    """T5: NO_AUTO_BLOCK -> ไม่มีคำสั่ง block ใด ๆ ถูกส่ง"""
    pipeline = build_pipeline(allowlist={ALLOWLISTED_SRC})
    trace = feed(pipeline, events(ALLOWLISTED_SRC, 1))
    assert trace["decision"] == "NO_AUTO_BLOCK"
    assert trace["t_block_cmd"] is None
    assert trace["t_block_verified"] is None


def test_failed_enforcement_records_command_but_not_verified():
    """command ถูกส่งแล้วล้ม -> t_block_cmd มี แต่ t_block_verified ต้อง None

    (command success ≠ enforcement success — ห้ามนับว่า verified)
    """
    pipeline = build_pipeline()
    pipeline.lifecycle = FakeLifecycle(ok=False)
    trace = feed(pipeline, events(TEST_SRC, 1))
    assert trace["t_block_cmd"] is not None
    assert trace["t_block_verified"] is None


def test_monotonic_and_wall_clock_both_present():
    """monotonic ใช้วัด latency / wall clock ใช้เป็นหลักฐาน — ต้องมีทั้งคู่"""
    trace = feed(build_pipeline(), events(TEST_SRC, 1))
    assert isinstance(trace["t3_decision"], float)
    assert isinstance(trace["t_decision"], str)


# ---- 3. M1–M4 คำนวณจากค่าที่บันทึกได้จริง ----
def test_metrics_m1_to_m4_computable_from_stored_row(repo, tmp_path):
    # ใช้ lifecycle จริง (BlockStore เดียวกับ audit DB) เพื่อให้ audit chain ครบ
    # -> พิสูจน์ว่า timestamp ถูกเก็บได้พร้อมกับ audit trail ไม่ใช่แยกโลกกัน
    from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
    from security_engine.lifecycle.block_store import BlockStore

    pipeline = build_pipeline(repository=repo)
    pipeline.lifecycle = BlockLifecycleManager(
        FakeEnforcer(), BlockStore(repo.db_path), repository=repo)
    trace = feed(pipeline, events(TEST_SRC, 1))
    repo.save_experiment_timestamps(
        "T4",
        t_event=trace["t_event"], t_detection=trace["t_detection"],
        t_decision=trace["t_decision"], t_block_cmd=trace["t_block_cmd"],
        t_block_verified=trace["t_block_verified"], notes="run=1")

    row = repo.get_experiment_timestamps("T4")[0]
    t = {k: datetime.fromisoformat(row[k]) for k in
         ("t_event", "t_detection", "t_decision", "t_block_cmd", "t_block_verified")}

    m1 = (t["t_detection"] - t["t_event"]).total_seconds() * 1000
    m2 = (t["t_decision"] - t["t_detection"]).total_seconds() * 1000
    m3 = (t["t_block_verified"] - t["t_decision"]).total_seconds() * 1000
    m4 = (t["t_block_verified"] - t["t_event"]).total_seconds() * 1000
    for value in (m1, m2, m3, m4):
        assert value >= 0
    assert m4 == pytest.approx(m1 + m2 + m3, abs=1e-6)

    # ส่วนย่อยของ M3 ที่ §14.1 แยกไว้
    round_trip = (t["t_block_cmd"] - t["t_decision"]).total_seconds() * 1000
    verification = (t["t_block_verified"] - t["t_block_cmd"]).total_seconds() * 1000
    assert round_trip >= 0 and verification >= 0
    assert m3 == pytest.approx(round_trip + verification, abs=1e-6)


def test_string_timestamps_from_trace_are_stored_unchanged(repo):
    trace = feed(build_pipeline(), events(TEST_SRC, 1))
    repo.save_experiment_timestamps("T4", t_decision=trace["t_decision"])
    assert repo.get_experiment_timestamps("T4")[0]["t_decision"] == trace["t_decision"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
