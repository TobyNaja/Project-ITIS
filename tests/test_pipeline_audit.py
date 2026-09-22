"""
tests/test_pipeline_audit.py — STEP 5B: pipeline -> audit persistence

ใช้ CorrelationEngine ตัวจริง + AuditRepository ตัวจริง + lifecycle ปลอม (ไม่แตะ pfSense)

    event -> security_events -> correlated_patterns -> risk_assessments -> decisions
    ALERT / NO_AUTO_BLOCK -> actions.action = ALERT
    MONITOR -> ไม่มี action
    BLOCK -> decision ถูกบันทึก แต่ actions/active_blocks เป็นงานของ STEP 5C

แยกจาก tests/test_pipeline.py (unit เดิมที่ไม่มี DB) เพื่อให้ไฟล์เดิมยังพิสูจน์ว่า
pipeline ทำงานได้โดยไม่ต้องมี repository
"""
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.correlation.engine import CorrelationEngine
from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import (
    RuleEngine, BLOCK, ALERT, MONITOR, NO_AUTO_BLOCK,
)
from security_engine.policy.rules_config import load_rules
from security_engine.storage.repository import (
    AuditRepository, AuditPersistenceError, DB_ID_KEY, ACTION_ALERT, NOT_APPLICABLE,
)
from security_engine.storage.schema import connect

SRC = "198.51.100.77"
T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)


class FakeResult:
    """contract เดียวกับ EnforcementResult (repository อ่าน field พวกนี้)"""
    def __init__(self, ip=None, command_ok=True, verified=True, action="add"):
        self.action = action
        self.ip = ip
        self.command_ok = command_ok
        self.verified = verified
        self.status = "ENFORCED" if command_ok and verified else "FAILED"

    @property
    def success(self):
        return self.command_ok and self.verified


class FakeLifecycle:
    """แทน BlockLifecycleManager — ไม่แตะ pfSense

    เขียน active_blocks เองเหมือน manager ตัวจริง (เพื่อให้ link action_id ทำงานได้)
    โดยไม่ import lifecycle จริง — integration กับของจริงอยู่ใน test_audit_chain.py
    """
    def __init__(self, db_path=None, block_ok=True):
        self.db_path = db_path
        self.block_ok = block_ok
        self.blocked = []

    def block(self, decision):
        self.blocked.append(decision.src_ip)
        if self.block_ok and self.db_path is not None:
            with connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO active_blocks "
                    "(src_ip, blocked_at, expires_at, status) VALUES (?,?,?,?)",
                    (decision.src_ip, T0.isoformat(),
                     (T0 + timedelta(seconds=decision.block_duration)).isoformat(),
                     "ACTIVE"))
                conn.commit()
        return FakeResult(ip=decision.src_ip,
                          command_ok=self.block_ok, verified=self.block_ok)


def eve(severity, offset=0.0, src=SRC, dest="192.0.2.10"):
    ts = (T0 + timedelta(seconds=offset)).isoformat()
    return {"src_ip": src, "dest_ip": dest, "severity": severity,
            "signature": "ET TEST", "signature_id": 2001219, "event_type": "alert",
            "timestamp": ts, "received_at": ts}


def build_audited_pipeline(tmp_path, allowlist=None):
    repo = AuditRepository(tmp_path / "audit.db")
    corr = CorrelationEngine(window_seconds=10, min_events=5)
    rule = RuleEngine(load_rules(), allowlist=allowlist or set())
    life = FakeLifecycle(db_path=repo.db_path)
    pipe = SecurityPipeline(corr, rule, life, lock=threading.Lock(), repository=repo)
    return pipe, repo, life


def feed(pipe, severity, count=5, src=SRC):
    trace = None
    for i in range(count):
        trace = pipe.process(eve(severity, offset=i * 0.5, src=src))
    return trace


def rows(repo, table):
    with connect(repo.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def break_db(monkeypatch):
    monkeypatch.setattr(
        "security_engine.storage.repository.connect",
        lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))


# ---- 1. security_events ----
def test_every_event_is_persisted(tmp_path):
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    feed(pipe, severity=1, count=5)
    assert len(rows(repo, "security_events")) == 5


def test_event_gets_db_id(tmp_path):
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    e = eve(1)
    pipe.process(e)
    assert e[DB_ID_KEY] == rows(repo, "security_events")[0]["id"]


def test_security_event_fields(tmp_path):
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    pipe.process(eve(2))
    row = rows(repo, "security_events")[0]
    assert row["src_ip"] == SRC
    assert row["dst_ip"] == "192.0.2.10"
    assert row["severity"] == 2
    assert row["event_type"] == "alert"


def test_event_without_correlation_has_no_pattern_or_decision(tmp_path):
    """T1/T2: ยังไม่ถึงเกณฑ์ correlate -> มีแค่ security_events"""
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    feed(pipe, severity=1, count=3)
    assert len(rows(repo, "security_events")) == 3
    assert rows(repo, "correlated_patterns") == []
    assert rows(repo, "risk_assessments") == []
    assert rows(repo, "decisions") == []
    assert rows(repo, "actions") == []


# ---- 2. correlated_patterns ----
def test_pattern_event_ids_match_security_events(tmp_path):
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    feed(pipe, severity=1, count=5)

    patterns = rows(repo, "correlated_patterns")
    assert len(patterns) == 1
    event_ids = json.loads(patterns[0]["event_ids"])
    assert event_ids == [r["id"] for r in rows(repo, "security_events")]
    assert patterns[0]["event_count"] == 5
    assert patterns[0]["max_severity"] == 1
    assert patterns[0]["src_ip"] == SRC
    assert len(repo.get_security_events(event_ids)) == 5


# ---- 3. risk_assessments ----
def test_risk_assessment_persisted_with_factors(tmp_path):
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    feed(pipe, severity=1, count=5)

    assessment = rows(repo, "risk_assessments")[0]
    assert assessment["pattern_id"] == rows(repo, "correlated_patterns")[0]["id"]
    assert (assessment["severity_score"], assessment["frequency_score"],
            assessment["temporal_score"], assessment["context_score"]) == \
        (75.0, 70.0, 100.0, 80.0)
    assert assessment["weight_set"] == "A"
    assert assessment["risk_score"] == 79.5
    assert assessment["risk_level"] == "HIGH"


# ---- 4. decisions: ทุก Decision ที่ pipeline สร้าง ----
def test_block_decision_persisted(tmp_path):
    pipe, repo, life = build_audited_pipeline(tmp_path)
    trace = feed(pipe, severity=1, count=5)

    decision = rows(repo, "decisions")[0]
    assert trace["decision"] == BLOCK
    assert decision["decision"] == BLOCK
    assert decision["rule_id"] == "RULE-001"
    assert decision["allowlisted"] == 0
    assert decision["assessment_id"] == rows(repo, "risk_assessments")[0]["id"]
    assert trace["decision_id"] == decision["id"]
    assert life.blocked == [SRC]                 # lifecycle ยังทำงานเหมือนเดิม


def test_alert_decision_creates_alert_action(tmp_path):
    pipe, repo, life = build_audited_pipeline(tmp_path)
    trace = feed(pipe, severity=2, count=5)

    assert trace["decision"] == ALERT
    action = rows(repo, "actions")[0]
    assert action["action"] == ACTION_ALERT
    assert action["decision_id"] == rows(repo, "decisions")[0]["id"]
    assert action["command_result"] == NOT_APPLICABLE
    assert action["verify_result"] == NOT_APPLICABLE
    assert action["duration_sec"] is None
    assert action["src_ip"] == SRC
    assert life.blocked == []


def test_no_auto_block_persists_allowlisted_and_alert_action(tmp_path):
    pipe, repo, life = build_audited_pipeline(tmp_path, allowlist={SRC})
    trace = feed(pipe, severity=1, count=5)

    assert trace["decision"] == NO_AUTO_BLOCK
    decision = rows(repo, "decisions")[0]
    assert decision["decision"] == NO_AUTO_BLOCK
    assert decision["rule_id"] == "RULE-003"
    assert decision["allowlisted"] == 1           # มาจาก Decision ไม่ได้ derive จาก rule_id
    assert rows(repo, "actions")[0]["action"] == ACTION_ALERT
    assert life.blocked == []


def test_monitor_decision_has_no_action(tmp_path):
    pipe, repo, life = build_audited_pipeline(tmp_path)
    trace = feed(pipe, severity=3, count=5)

    assert trace["decision"] == MONITOR
    decision = rows(repo, "decisions")[0]
    assert decision["decision"] == MONITOR
    assert decision["rule_id"] == "DEFAULT"
    assert rows(repo, "actions") == []            # MONITOR ไม่ใช่ response action
    assert life.blocked == []


def test_decision_reason_is_persisted(tmp_path):
    """FR-14: reason ต้องอธิบายได้ว่ากฎไหน match เพราะอะไร"""
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    feed(pipe, severity=1, count=5)
    reason = rows(repo, "decisions")[0]["reason"]
    assert "RULE-001" in reason and "severity" in reason and "events" in reason


def test_block_creates_block_action_and_links_active_block(tmp_path):
    """STEP 5C: BLOCK สำเร็จ -> actions.action = BLOCK -> active_blocks.action_id"""
    pipe, repo, _ = build_audited_pipeline(tmp_path)
    trace = feed(pipe, severity=1, count=5)

    action = rows(repo, "actions")[0]
    assert action["action"] == "BLOCK"
    assert action["decision_id"] == rows(repo, "decisions")[0]["id"]
    assert action["duration_sec"] == 300
    assert action["command_result"] == "SUCCESS"
    assert action["verify_result"] == "VERIFIED"
    assert trace["action_id"] == action["id"]
    assert rows(repo, "active_blocks")[0]["action_id"] == action["id"]


# ---- 5. pipeline ที่ไม่มี repository ยังทำงานเหมือนเดิม ----
def test_pipeline_without_repository_still_decides(tmp_path):
    corr = CorrelationEngine(window_seconds=10, min_events=5)
    life = FakeLifecycle()                       # ไม่มี DB เลย
    pipe = SecurityPipeline(corr, RuleEngine(load_rules()), life,
                            lock=threading.Lock())
    trace = feed(pipe, severity=1, count=5)
    assert trace["decision"] == BLOCK
    assert trace["decision_id"] is None
    assert life.blocked == [SRC]


# ---- 6. persistence failure ----
def test_persistence_failure_raises_audit_error(tmp_path, monkeypatch):
    pipe, _, _ = build_audited_pipeline(tmp_path)
    break_db(monkeypatch)
    with pytest.raises(AuditPersistenceError):
        pipe.process(eve(1))


def test_audit_failure_before_enforcement_leaves_firewall_untouched(tmp_path, monkeypatch):
    """DB ล้มก่อนสั่ง pfSense -> lifecycle ไม่ถูกเรียก = ไม่มี firewall state ค้าง"""
    pipe, _, life = build_audited_pipeline(tmp_path)
    for i in range(4):
        pipe.process(eve(1, offset=i * 0.5))       # ยังไม่ครบ 5

    break_db(monkeypatch)
    with pytest.raises(AuditPersistenceError):
        pipe.process(eve(1, offset=2.0))           # event ที่ 5 -> ปกติจะ BLOCK
    assert life.blocked == []


def test_audit_error_is_not_enforcement_error(tmp_path, monkeypatch):
    from security_engine.enforcement.pfsense_enforcer import EnforcementError

    pipe, _, _ = build_audited_pipeline(tmp_path)
    break_db(monkeypatch)
    with pytest.raises(AuditPersistenceError) as exc:
        pipe.process(eve(1))
    assert not isinstance(exc.value, EnforcementError)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
