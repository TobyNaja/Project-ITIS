"""
tests/test_audit_chain.py — STEP 5C: audit chain แบบครบวง (integration)

ของจริงทุกชั้นยกเว้น pfSense:
    CorrelationEngine + RiskModel + RuleEngine(rules.yaml)
    + BlockLifecycleManager + BlockStore (SQLite ไฟล์เดียวกับ AuditRepository)
    + FakeEnforcer แทน SSH

พิสูจน์ chain ตาม §3.4:
    active_blocks -> actions -> decisions -> risk_assessments -> correlated_patterns
                                                              -> security_events

และเส้นแบ่งตาม NFR-06:
    enforcement success + audit failure = สองสถานะที่แยกกัน
    ผลของ pfSense ห้ามถูกเขียนทับเพราะ DB audit ล้ม
"""
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.correlation.engine import CorrelationEngine
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
from security_engine.lifecycle.block_store import BlockStore
from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import RuleEngine, BLOCK
from security_engine.policy.rules_config import load_rules
from security_engine.storage.repository import (
    AuditRepository, AuditPersistenceError, ACTION_BLOCK,
    COMMAND_SUCCESS, COMMAND_FAIL, VERIFY_VERIFIED, VERIFY_FAILED,
)
from security_engine.storage.schema import connect, STATUS_ACTIVE

SRC = "198.51.100.77"
T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)


class FakeEnforcementResult:
    """contract เดียวกับ EnforcementResult ของ pfsense_enforcer"""
    def __init__(self, action, ip, command_ok, verified):
        self.action = action
        self.ip = ip
        self.command_ok = command_ok
        self.verified = verified
        self.status = "ENFORCED" if command_ok and verified else "FAILED"

    @property
    def success(self):
        return self.command_ok and self.verified


class FakeEnforcer:
    """แทน PFSenseEnforcer — ไม่ยิง SSH"""
    def __init__(self, command_ok=True, verified=True):
        self.command_ok = command_ok
        self.verified = verified
        self.added = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeEnforcementResult("add", ip, self.command_ok, self.verified)

    def remove_block(self, ip):
        return FakeEnforcementResult("remove", ip, True, True)

    def is_blocked(self, ip):
        return ip in self.added


def eve(severity=1, offset=0.0, src=SRC, dest="192.0.2.10"):
    ts = (T0 + timedelta(seconds=offset)).isoformat()
    return {"src_ip": src, "dest_ip": dest, "severity": severity,
            "signature": "ET SCAN test", "signature_id": 2001219,
            "event_type": "alert", "timestamp": ts, "received_at": ts}


def build_stack(tmp_path, command_ok=True, verified=True):
    """ทุกชั้นใช้ไฟล์ DB เดียวกัน — audit chain จึง join ข้ามตารางได้จริง"""
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    enforcer = FakeEnforcer(command_ok=command_ok, verified=verified)
    lifecycle = BlockLifecycleManager(enforcer, BlockStore(db))
    pipe = SecurityPipeline(
        CorrelationEngine(window_seconds=10, min_events=5),
        RuleEngine(load_rules()),
        lifecycle,
        lock=threading.Lock(),
        repository=repo,
    )
    return pipe, repo, enforcer, lifecycle


def feed_block_pattern(pipe, severity=1, count=5):
    trace = None
    for i in range(count):
        trace = pipe.process(eve(severity, offset=i * 0.5))
    return trace


def rows(repo, table):
    with connect(repo.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


# ---- 1. BLOCK สำเร็จ -> chain ครบ ----
def test_block_links_active_block_to_action(tmp_path):
    pipe, repo, enforcer, _ = build_stack(tmp_path)
    trace = feed_block_pattern(pipe)

    assert trace["decision"] == BLOCK
    assert enforcer.added == [SRC]

    action = rows(repo, "actions")[0]
    block = rows(repo, "active_blocks")[0]
    assert action["action"] == ACTION_BLOCK
    assert action["command_result"] == COMMAND_SUCCESS
    assert action["verify_result"] == VERIFY_VERIFIED
    assert action["duration_sec"] == 300
    assert block["status"] == STATUS_ACTIVE
    assert block["action_id"] == action["id"]
    assert trace["action_id"] == action["id"]


def test_full_chain_is_traceable_from_active_block(tmp_path):
    """ไล่ย้อน active_blocks -> ... -> security_events ด้วย FK จริง"""
    pipe, repo, _, _ = build_stack(tmp_path)
    feed_block_pattern(pipe)

    chain = repo.get_audit_chain(SRC)
    assert chain is not None
    assert chain["status"] == STATUS_ACTIVE
    assert chain["action"] == ACTION_BLOCK
    assert chain["decision"] == "BLOCK"
    assert chain["rule_id"] == "RULE-001"
    assert chain["allowlisted"] == 0
    assert chain["risk_score"] == 79.5
    assert chain["risk_level"] == "HIGH"
    assert chain["weight_set"] == "A"
    assert (chain["severity_score"], chain["frequency_score"],
            chain["temporal_score"], chain["context_score"]) == (75.0, 70.0, 100.0, 80.0)
    assert chain["event_count"] == 5
    assert chain["max_severity"] == 1

    event_ids = json.loads(chain["event_ids"])
    assert len(event_ids) == 5
    events = repo.get_security_events(event_ids)
    assert len(events) == 5
    assert {e["src_ip"] for e in events} == {SRC}


def test_chain_reason_explains_decision(tmp_path):
    """FR-14: อ่าน reason จาก DB แล้วต้องอธิบายได้ว่าทำไมถึง BLOCK"""
    pipe, repo, _, _ = build_stack(tmp_path)
    feed_block_pattern(pipe)

    chain = repo.get_audit_chain(SRC)
    assert "RULE-001" in chain["reason"]
    assert "severity" in chain["reason"]
    assert "events" in chain["reason"]
    assert "window" in chain["reason"]


def test_one_row_per_table_for_one_block(tmp_path):
    pipe, repo, _, _ = build_stack(tmp_path)
    feed_block_pattern(pipe)

    assert len(rows(repo, "security_events")) == 5
    assert len(rows(repo, "correlated_patterns")) == 1
    assert len(rows(repo, "risk_assessments")) == 1
    assert len(rows(repo, "decisions")) == 1
    assert len(rows(repo, "actions")) == 1
    assert len(rows(repo, "active_blocks")) == 1


# ---- 2. enforcement ล้ม -> ไม่มี audit ที่บอกว่าสำเร็จ ----
def test_failed_enforcement_records_failure_without_active_block(tmp_path):
    """pfSense ล้ม -> ไม่มี active_blocks (lifecycle ไม่เขียน) และ action ต้องบอกว่า FAIL"""
    pipe, repo, enforcer, _ = build_stack(tmp_path, command_ok=False, verified=False)
    trace = feed_block_pattern(pipe)

    assert trace["decision"] == BLOCK
    assert trace["t4_enforce_req"] is not None
    assert trace["t5_enforce_ok"] is None          # enforcement ไม่สำเร็จ

    action = rows(repo, "actions")[0]
    assert action["action"] == ACTION_BLOCK
    assert action["command_result"] == COMMAND_FAIL
    assert action["verify_result"] == VERIFY_FAILED
    assert rows(repo, "active_blocks") == []       # ไม่มี block ปลอมใน DB
    assert repo.get_audit_chain(SRC) is None       # chain ขาดตรง active_blocks จริง ๆ


def test_command_ok_but_verify_failed_is_not_a_successful_block(tmp_path):
    """command success ≠ enforcement success (FR-08)"""
    pipe, repo, _, _ = build_stack(tmp_path, command_ok=True, verified=False)
    trace = feed_block_pattern(pipe)

    action = rows(repo, "actions")[0]
    assert action["command_result"] == COMMAND_SUCCESS
    assert action["verify_result"] == VERIFY_FAILED
    assert trace["t5_enforce_ok"] is None
    assert rows(repo, "active_blocks") == []


# ---- 3. enforcement สำเร็จ + audit ล้ม ----
def test_audit_failure_after_successful_enforcement(tmp_path, monkeypatch):
    """pfSense block สำเร็จแล้ว DB ล้ม -> AuditPersistenceError
    แต่ firewall state จริงยังเป็น BLOCKED และผล enforcement ห้ามถูกแก้ย้อนหลัง"""
    pipe, repo, enforcer, lifecycle = build_stack(tmp_path)

    # 4 event แรกผ่านปกติ (ยังไม่ match)
    for i in range(4):
        pipe.process(eve(1, offset=i * 0.5))

    real_connect = connect
    calls = {"n": 0}

    def flaky_connect(*args, **kwargs):
        """ปล่อย 4 call แรกของ event ที่ 5 (security_event, pattern, risk, decision)
        แล้วล้มตอนบันทึก action — คือ audit ล้ม *หลัง* enforcement เกิดขึ้นแล้ว"""
        calls["n"] += 1
        if calls["n"] > 4:
            raise sqlite3.OperationalError("database is locked")
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("security_engine.storage.repository.connect", flaky_connect)

    with pytest.raises(AuditPersistenceError):
        pipe.process(eve(1, offset=2.0))

    # enforcement เกิดขึ้นจริงและสำเร็จ — ไม่ถูกย้อนหรือแปลงเป็น BLOCK_FAILED
    assert enforcer.added == [SRC]
    assert enforcer.is_blocked(SRC) is True


def test_enforcement_result_object_unchanged_by_audit_failure(tmp_path, monkeypatch):
    """ผลลัพธ์ของ lifecycle.block() ต้องคงค่า success เดิมแม้ audit จะล้ม"""
    pipe, repo, enforcer, lifecycle = build_stack(tmp_path)
    captured = {}

    real_block = lifecycle.block

    def spy_block(decision):
        result = real_block(decision)
        captured["result"] = result
        return result

    monkeypatch.setattr(lifecycle, "block", spy_block)
    monkeypatch.setattr(
        "security_engine.storage.repository.AuditRepository.save_enforcement_action",
        lambda *a, **k: (_ for _ in ()).throw(
            AuditPersistenceError("save_action ล้มเหลว")))

    with pytest.raises(AuditPersistenceError):
        feed_block_pattern(pipe)

    assert captured["result"].success is True
    assert captured["result"].status == "ENFORCED"


def test_active_block_row_survives_audit_link_failure(tmp_path, monkeypatch):
    """link ล้ม -> active_blocks ยังอยู่ (firewall ถูก block จริง) แค่ action_id ยัง NULL"""
    pipe, repo, enforcer, _ = build_stack(tmp_path)
    monkeypatch.setattr(
        "security_engine.storage.repository.AuditRepository.link_active_block_action",
        lambda *a, **k: (_ for _ in ()).throw(AuditPersistenceError("link ล้มเหลว")))

    with pytest.raises(AuditPersistenceError):
        feed_block_pattern(pipe)

    block = rows(repo, "active_blocks")[0]
    assert block["status"] == STATUS_ACTIVE
    assert block["action_id"] is None              # transient state ที่ยังไม่ถูกผูก
    assert enforcer.is_blocked(SRC) is True


# ---- 4. lifecycle behavior เดิมไม่เปลี่ยน ----
def test_lifecycle_still_writes_active_block_itself(tmp_path):
    """STEP 5C ไม่แตะ lifecycle — manager ยังเป็นคนสร้าง active_blocks เอง"""
    pipe, repo, _, lifecycle = build_stack(tmp_path)
    feed_block_pattern(pipe)

    stored = lifecycle.store.get_block(SRC)
    assert stored["status"] == STATUS_ACTIVE
    assert stored["action_id"] is not None         # ผูกกับ actions แล้ว
    # STEP 5D: ไม่เก็บ rule_id/reason ซ้ำใน active_blocks อีกต่อไป
    assert "rule_id" not in stored and "reason" not in stored


# ---- 5. STEP 5D: ไม่เก็บ rule_id/reason ซ้ำใน active_blocks ----
def test_rule_id_and_reason_reachable_without_duplication(tmp_path):
    """regression: ย้อน active_blocks -> actions -> decisions แล้วได้ rule_id/reason ครบ
    โดยที่ active_blocks ไม่มีสองคอลัมน์นี้เก็บซ้ำอีกแล้ว"""
    pipe, repo, _, _ = build_stack(tmp_path)
    feed_block_pattern(pipe)

    with connect(repo.db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute(
            "SELECT d.rule_id, d.reason, d.decision, d.allowlisted "
            "FROM active_blocks ab "
            "JOIN actions a ON a.id = ab.action_id "
            "JOIN decisions d ON d.id = a.decision_id "
            "WHERE ab.src_ip = ?", (SRC,)).fetchone())
        block_columns = {r[1] for r in conn.execute("PRAGMA table_info(active_blocks)")}

    assert row["rule_id"] == "RULE-001"
    assert row["decision"] == "BLOCK"
    assert row["allowlisted"] == 0
    assert "RULE-001" in row["reason"] and "severity" in row["reason"]

    assert block_columns == {"src_ip", "blocked_at", "expires_at", "status", "action_id"}
    assert "rule_id" not in block_columns and "reason" not in block_columns


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
