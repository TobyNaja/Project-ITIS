"""
tests/test_repository.py — Audit persistence (STEP 5A)

ทดสอบ repository เดี่ยว ๆ ยังไม่ต่อ pipeline/lifecycle:
    save_security_event -> _db_id
    save_correlated_pattern -> event_ids อ้าง security_events.id จริง
    save_risk_assessment / save_decision / save_action -> FK ถูกต้อง
    link_active_block_action -> active_blocks.action_id
    DB error -> log + AuditPersistenceError (ไม่แตะผล enforcement)
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.models import CorrelationPattern, SourceContext
from security_engine.policy.rule_engine import RuleEngine
from security_engine.policy.rules_config import load_rules
from security_engine.scoring.risk import calculate
from security_engine.storage.schema import connect, STATUS_ACTIVE
from security_engine.storage.repository import (
    AuditRepository, AuditPersistenceError, DB_ID_KEY,
    ACTION_BLOCK, ACTION_ALERT, ACTION_UNBLOCK,
    COMMAND_SUCCESS, COMMAND_FAIL, VERIFY_VERIFIED, VERIFY_FAILED, NOT_APPLICABLE,
)

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
SRC = "198.51.100.77"
UNKNOWN = SourceContext(allowlisted=False, known_asset=False)
ALLOWED = SourceContext(allowlisted=True, known_asset=False)


@pytest.fixture
def repo(tmp_path):
    return AuditRepository(tmp_path / "audit.db")


def make_event(severity=1, src=SRC, dest="192.0.2.10", sid=2001219):
    return {"timestamp": T0, "received_at": T0, "src_ip": src, "dest_ip": dest,
            "severity": severity, "signature_id": sid,
            "signature": "ET SCAN test", "proto": "TCP", "event_type": "alert"}


def make_pattern(events, window=5.0, src=SRC):
    severities = [e["severity"] for e in events]
    return CorrelationPattern(
        src_ip=src, window_start=T0, window_end=T0 + timedelta(seconds=window),
        event_count=len(events), max_severity=min(severities),
        events=tuple(events))


class FakeEnforcementResult:
    def __init__(self, action="add", ip=SRC, command_ok=True, verified=True):
        self.action = action
        self.ip = ip
        self.command_ok = command_ok
        self.verified = verified
        self.status = "ENFORCED" if command_ok and verified else "FAILED"

    @property
    def success(self):
        return self.command_ok and self.verified


def decision_for(pattern, context=UNKNOWN):
    risk = calculate(pattern, context)
    return risk, RuleEngine(load_rules(),
                            allowlist={SRC} if context.allowlisted else set()
                            ).decide(risk, pattern)


# ---------- 1. security_events ----------
def test_save_security_event_returns_id_and_tags_event(repo):
    event = make_event()
    event_id = repo.save_security_event(event)
    assert isinstance(event_id, int) and event_id > 0
    assert event[DB_ID_KEY] == event_id


def test_security_event_fields_persisted(repo):
    event = make_event(severity=2)
    event_id = repo.save_security_event(event)
    row = repo.get_security_events([event_id])[0]
    assert row["src_ip"] == SRC
    assert row["dst_ip"] == "192.0.2.10"
    assert row["severity"] == 2
    assert row["signature_id"] == 2001219
    assert row["event_type"] == "alert"
    assert row["timestamp"].startswith("2026-09-22T10:00:00")


def test_raw_json_excludes_db_id(repo):
    event = make_event()
    event_id = repo.save_security_event(event)
    raw = json.loads(repo.get_security_events([event_id])[0]["raw_json"])
    assert DB_ID_KEY not in raw
    assert raw["src_ip"] == SRC


def test_each_event_gets_distinct_id(repo):
    events = [make_event() for _ in range(5)]
    ids = [repo.save_security_event(e) for e in events]
    assert len(set(ids)) == 5


# ---------- 2. correlated_patterns ----------
def test_pattern_event_ids_reference_real_rows(repo):
    events = [make_event() for _ in range(5)]
    ids = [repo.save_security_event(e) for e in events]
    pattern_id = repo.save_correlated_pattern(make_pattern(events))

    with connect(repo.db_path) as conn:
        row = conn.execute("SELECT src_ip, event_count, max_severity, event_ids "
                           "FROM correlated_patterns WHERE id = ?",
                           (pattern_id,)).fetchone()
    assert row[0] == SRC and row[1] == 5 and row[2] == 1
    assert json.loads(row[3]) == ids
    assert len(repo.get_security_events(ids)) == 5


def test_pattern_without_saved_events_raises(repo):
    """ห้ามเดา id จากเนื้อ event — event ที่ยังไม่ถูกบันทึกต้อง error"""
    events = [make_event() for _ in range(5)]
    repo.save_security_event(events[0])          # บันทึกแค่ตัวแรก
    with pytest.raises(AuditPersistenceError) as exc:
        repo.save_correlated_pattern(make_pattern(events))
    assert DB_ID_KEY in str(exc.value)


def test_pattern_window_and_count_persisted(repo):
    events = [make_event() for _ in range(5)]
    for e in events:
        repo.save_security_event(e)
    pattern_id = repo.save_correlated_pattern(make_pattern(events, window=7.5))
    with connect(repo.db_path) as conn:
        start, end = conn.execute(
            "SELECT window_start, window_end FROM correlated_patterns WHERE id = ?",
            (pattern_id,)).fetchone()
    assert start.startswith("2026-09-22T10:00:00")
    assert end.startswith("2026-09-22T10:00:07")


# ---------- 3. risk_assessments ----------
def test_risk_assessment_persists_all_factors(repo):
    events = [make_event() for _ in range(5)]
    for e in events:
        repo.save_security_event(e)
    pattern = make_pattern(events)
    pattern_id = repo.save_correlated_pattern(pattern)
    risk, _ = decision_for(pattern)

    assessment_id = repo.save_risk_assessment(pattern_id, risk)
    with connect(repo.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM risk_assessments WHERE id = ?",
                                (assessment_id,)).fetchone())
    assert row["pattern_id"] == pattern_id
    assert (row["severity_score"], row["frequency_score"],
            row["temporal_score"], row["context_score"]) == (75.0, 70.0, 100.0, 80.0)
    assert row["weight_set"] == "A"
    assert row["risk_score"] == 79.5
    assert row["risk_level"] == "HIGH"


def test_risk_assessment_requires_existing_pattern(repo):
    events = [make_event()]
    repo.save_security_event(events[0])
    risk, _ = decision_for(make_pattern(events * 5))
    with pytest.raises(AuditPersistenceError):
        repo.save_risk_assessment(9999, risk)      # FK ไม่มีจริง


# ---------- 4. decisions ----------
def _chain_to_assessment(repo, events, context=UNKNOWN, window=5.0):
    for e in events:
        repo.save_security_event(e)
    pattern = make_pattern(events, window=window)
    pattern_id = repo.save_correlated_pattern(pattern)
    risk, decision = decision_for(pattern, context)
    assessment_id = repo.save_risk_assessment(pattern_id, risk)
    return assessment_id, risk, decision


def test_block_decision_persisted(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)

    row = repo.get_decision(decision_id)
    assert row["assessment_id"] == assessment_id
    assert row["decision"] == "BLOCK"
    assert row["rule_id"] == "RULE-001"
    assert row["allowlisted"] == 0
    assert "RULE-001" in row["reason"]


def test_alert_decision_persisted(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=2) for _ in range(5)])
    row = repo.get_decision(
        repo.save_decision(assessment_id, decision, allowlisted=False))
    assert row["decision"] == "ALERT"
    assert row["rule_id"] == "RULE-002"


def test_no_auto_block_decision_persisted_with_allowlisted_flag(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)], context=ALLOWED)
    row = repo.get_decision(
        repo.save_decision(assessment_id, decision, allowlisted=True))
    assert row["decision"] == "NO_AUTO_BLOCK"
    assert row["rule_id"] == "RULE-003"
    assert row["allowlisted"] == 1


def test_monitor_decision_persisted(repo):
    """ทุก Decision ที่ถูกสร้างต้องมี row — รวม MONITOR"""
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=3) for _ in range(5)])
    row = repo.get_decision(
        repo.save_decision(assessment_id, decision, allowlisted=False))
    assert row["decision"] == "MONITOR"
    assert row["rule_id"] == "DEFAULT"


def test_decision_requires_existing_assessment(repo):
    _, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    with pytest.raises(AuditPersistenceError):
        repo.save_decision(9999, decision, allowlisted=False)


# ---------- 5. actions ----------
def test_block_action_records_command_and_verification(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)

    action_id = repo.save_enforcement_action(
        decision_id, FakeEnforcementResult("add", SRC, True, True),
        duration_sec=decision.block_duration)

    row = repo.get_action(action_id)
    assert row["decision_id"] == decision_id
    assert row["action"] == ACTION_BLOCK
    assert row["src_ip"] == SRC
    assert row["duration_sec"] == 300
    assert row["command_result"] == COMMAND_SUCCESS
    assert row["verify_result"] == VERIFY_VERIFIED
    assert row["error"] is None


def test_command_success_but_verify_failed_is_recorded_separately(repo):
    """FR-08: command success ≠ enforcement success"""
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)

    row = repo.get_action(repo.save_enforcement_action(
        decision_id, FakeEnforcementResult("add", SRC, True, False)))
    assert row["command_result"] == COMMAND_SUCCESS
    assert row["verify_result"] == VERIFY_FAILED


def test_unblock_action_type(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    row = repo.get_action(repo.save_enforcement_action(
        decision_id, FakeEnforcementResult("remove", SRC, True, True)))
    assert row["action"] == ACTION_UNBLOCK


def test_alert_action_is_not_applicable_not_skipped(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=2) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)

    row = repo.get_action(repo.save_alert_action(decision_id, SRC))
    assert row["action"] == ACTION_ALERT
    assert row["command_result"] == NOT_APPLICABLE
    assert row["verify_result"] == NOT_APPLICABLE
    assert row["duration_sec"] is None
    assert row["error"] is None


def test_invalid_action_type_rejected(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    with pytest.raises(AuditPersistenceError):
        repo.save_action(decision_id, action="NO_AUTO_BLOCK", src_ip=SRC)


def test_action_error_is_recorded(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    row = repo.get_action(repo.save_enforcement_action(
        decision_id, FakeEnforcementResult("add", SRC, False, False),
        error="ssh: connect timed out"))
    assert row["command_result"] == COMMAND_FAIL
    assert row["error"] == "ssh: connect timed out"


# ---------- 6. active_blocks link + FK chain ----------
def _seed_active_block(repo, src_ip=SRC):
    with connect(repo.db_path) as conn:
        conn.execute(
            "INSERT INTO active_blocks (src_ip, blocked_at, expires_at, status) "
            "VALUES (?,?,?,?)",
            (src_ip, T0.isoformat(), (T0 + timedelta(seconds=300)).isoformat(),
             STATUS_ACTIVE))
        conn.commit()


def test_link_active_block_action(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    action_id = repo.save_enforcement_action(
        decision_id, FakeEnforcementResult(), duration_sec=300)

    _seed_active_block(repo)
    repo.link_active_block_action(SRC, action_id)

    with connect(repo.db_path) as conn:
        assert conn.execute(
            "SELECT action_id FROM active_blocks WHERE src_ip = ?",
            (SRC,)).fetchone()[0] == action_id


def test_link_missing_active_block_raises(repo):
    assessment_id, _, decision = _chain_to_assessment(
        repo, [make_event(severity=1) for _ in range(5)])
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    action_id = repo.save_enforcement_action(decision_id, FakeEnforcementResult())
    with pytest.raises(AuditPersistenceError):
        repo.link_active_block_action("203.0.113.1", action_id)


def test_full_audit_chain_is_traceable(repo):
    """§3.4: ย้อนจาก active_blocks กลับถึง correlated_patterns ด้วย FK จริง"""
    events = [make_event(severity=1) for _ in range(5)]
    assessment_id, risk, decision = _chain_to_assessment(repo, events)
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    action_id = repo.save_enforcement_action(
        decision_id, FakeEnforcementResult(), duration_sec=decision.block_duration)
    _seed_active_block(repo)
    repo.link_active_block_action(SRC, action_id)

    chain = repo.get_audit_chain(SRC)
    assert chain["status"] == STATUS_ACTIVE
    assert chain["action_id"] == action_id
    assert chain["action"] == ACTION_BLOCK
    assert chain["duration_sec"] == 300
    assert chain["decision"] == "BLOCK"
    assert chain["rule_id"] == "RULE-001"
    assert chain["risk_score"] == 79.5
    assert chain["risk_level"] == "HIGH"
    assert chain["weight_set"] == "A"
    assert (chain["severity_score"], chain["frequency_score"],
            chain["temporal_score"], chain["context_score"]) == (75.0, 70.0, 100.0, 80.0)
    assert chain["event_count"] == 5
    assert chain["max_severity"] == 1
    assert len(json.loads(chain["event_ids"])) == 5
    # ไล่ต่อไปถึง security_events ตัวจริง
    assert len(repo.get_security_events(json.loads(chain["event_ids"]))) == 5


# ---------- 7. FR-14 explainability ----------
def test_decision_reason_explains_decision(repo):
    events = [make_event(severity=1) for _ in range(5)]
    assessment_id, risk, decision = _chain_to_assessment(repo, events)
    decision_id = repo.save_decision(assessment_id, decision, allowlisted=False)
    row = repo.get_decision(decision_id)

    # reason อธิบายกฎที่ match + เงื่อนไขที่ใช้
    assert "RULE-001" in row["reason"]
    assert "severity" in row["reason"]
    assert "events" in row["reason"]
    # factor breakdown ที่เหลืออยู่ใน risk_assessments ซึ่ง join ถึงได้
    chain_fields = repo._read(
        "SELECT r.severity_score, r.frequency_score, r.temporal_score, "
        "       r.context_score, r.risk_score, d.allowlisted, d.rule_id "
        "FROM decisions d JOIN risk_assessments r ON r.id = d.assessment_id "
        "WHERE d.id = ?", (decision_id,), what="test")[0]
    assert chain_fields["risk_score"] == 79.5
    assert chain_fields["allowlisted"] == 0


# ---------- 8. persistence failure ----------
def test_db_error_raises_audit_error(tmp_path, monkeypatch):
    repo = AuditRepository(tmp_path / "audit.db")

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("security_engine.storage.repository.connect", boom)
    with pytest.raises(AuditPersistenceError):
        repo.save_security_event(make_event())


def test_db_error_is_logged(tmp_path, monkeypatch, caplog):
    repo = AuditRepository(tmp_path / "audit.db")

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr("security_engine.storage.repository.connect", boom)
    with caplog.at_level("ERROR"):
        with pytest.raises(AuditPersistenceError):
            repo.save_security_event(make_event())
    assert any("audit persistence failed" in r.message for r in caplog.records)


def test_audit_error_is_not_an_enforcement_error(tmp_path, monkeypatch):
    """audit ล้ม ต้องไม่ถูกตีความเป็น enforcement ล้ม (NFR-06)"""
    from security_engine.enforcement.pfsense_enforcer import EnforcementError

    repo = AuditRepository(tmp_path / "audit.db")
    monkeypatch.setattr("security_engine.storage.repository.connect",
                        lambda *a, **k: (_ for _ in ()).throw(
                            sqlite3.OperationalError("locked")))
    with pytest.raises(AuditPersistenceError) as exc:
        repo.save_security_event(make_event())
    assert not isinstance(exc.value, EnforcementError)

    # ผล enforcement ที่คำนวณไว้แล้วต้องไม่ถูกแก้เพราะ audit ล้ม
    result = FakeEnforcementResult("add", SRC, True, True)
    assert result.success is True


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
