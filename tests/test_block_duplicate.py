"""
tests/test_block_duplicate.py — STEP 6A: FR-11 duplicate ACTIVE block

requirement (§4.1 FR-11):
    IP ที่ ACTIVE อยู่แล้ว -> ไม่ block ซ้ำ ไม่สร้าง timer ซ้อน — log ว่า pattern เกิดซ้ำ

contract ที่ล็อก:
    ACTIVE                       -> ไม่เรียก enforcer, ไม่แตะ DB, ไม่เลื่อน expires_at
    EXPIRED / MANUALLY_REMOVED   -> block ใหม่ได้ตามปกติ

*** ปิดช่องว่าง ~290 วินาที *** — correlation cooldown กันซ้ำได้แค่ 10s
แต่ block duration คือ 300s ดังนั้น pattern ที่เกิดซ้ำหลัง cooldown ต้องไม่ยิง pfSense ใหม่
"""
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.correlation.engine import CorrelationEngine
from security_engine.lifecycle.block_lifecycle import (
    BlockLifecycleManager, DuplicateBlockResult, STATUS_DUPLICATE,
)
from security_engine.lifecycle.block_store import BlockStore
from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import Decision, RuleEngine, BLOCK
from security_engine.policy.rules_config import load_rules
from security_engine.storage.repository import AuditRepository
from security_engine.storage.schema import (
    connect, STATUS_ACTIVE, STATUS_EXPIRED, STATUS_MANUALLY_REMOVED,
)

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
IP = "198.51.100.77"


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
    def __init__(self, add_ok=True):
        self.add_ok = add_ok
        self.added = []
        self.removed = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeResult("add", ip, self.add_ok)

    def remove_block(self, ip):
        self.removed.append(ip)
        return FakeResult("remove", ip, True)

    def is_blocked(self, ip):
        return ip in self.added and ip not in self.removed


class FakeClock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t = self.t + timedelta(seconds=seconds)


def decision(duration=300, ip=IP):
    return Decision(action=BLOCK, rule_id="RULE-001", src_ip=ip,
                    reason="[RULE-001] severity=1", block_duration=duration)


@pytest.fixture
def lifecycle(tmp_path):
    store = BlockStore(tmp_path / "life.db")
    enforcer = FakeEnforcer()
    clock = FakeClock(T0)
    return BlockLifecycleManager(enforcer, store, clock=clock), store, enforcer, clock


# ---------- 1. lifecycle: duplicate ACTIVE ----------
def test_second_block_does_not_call_enforcer(lifecycle):
    mgr, store, enforcer, _ = lifecycle
    mgr.block(decision())
    mgr.block(decision())
    assert enforcer.added == [IP]                 # ยิง pfSense ครั้งเดียว


def test_second_block_returns_duplicate_result(lifecycle):
    mgr, _, _, _ = lifecycle
    mgr.block(decision())
    result = mgr.block(decision())
    assert isinstance(result, DuplicateBlockResult)
    assert result.duplicate is True
    assert result.success is False                # ไม่ใช่ enforcement ที่สำเร็จ
    assert result.command_ok is False             # ไม่มีคำสั่งถูกส่งเลย
    assert result.status == STATUS_DUPLICATE
    assert result.ip == IP


def test_expires_at_is_not_extended(lifecycle):
    """หัวใจของ FR-11: block ต้องหมดอายุตามเวลาที่ตั้งไว้ครั้งแรก"""
    mgr, store, _, clock = lifecycle
    mgr.block(decision(duration=300))
    first_expiry = store.get_block(IP)["expires_at"]

    clock.advance(100)                            # pattern เกิดซ้ำกลางทาง
    mgr.block(decision(duration=300))

    assert store.get_block(IP)["expires_at"] == first_expiry


def test_blocked_at_is_not_rewritten(lifecycle):
    mgr, store, _, clock = lifecycle
    mgr.block(decision())
    first_blocked_at = store.get_block(IP)["blocked_at"]
    clock.advance(100)
    mgr.block(decision())
    assert store.get_block(IP)["blocked_at"] == first_blocked_at


def test_only_one_active_row(lifecycle):
    mgr, store, _, _ = lifecycle
    for _ in range(5):
        mgr.block(decision())
    assert len(store.get_active_blocks()) == 1


def test_duplicate_is_logged(lifecycle, caplog):
    """FR-11 กำหนดให้ log ว่า pattern เกิดซ้ำระหว่าง block"""
    mgr, _, _, _ = lifecycle
    mgr.block(decision())
    with caplog.at_level(logging.INFO):
        mgr.block(decision())
    assert any("duplicate" in r.message for r in caplog.records)


def test_first_block_still_works(lifecycle):
    mgr, store, enforcer, _ = lifecycle
    result = mgr.block(decision())
    assert result.success is True
    assert getattr(result, "duplicate", False) is False
    assert store.get_block(IP)["status"] == STATUS_ACTIVE
    assert enforcer.added == [IP]


# ---------- 2. สถานะอื่นยัง block ใหม่ได้ ----------
def test_expired_block_can_be_blocked_again(lifecycle):
    mgr, store, enforcer, clock = lifecycle
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()                              # -> EXPIRED
    assert store.get_block(IP)["status"] == STATUS_EXPIRED

    result = mgr.block(decision())
    assert result.success is True
    assert enforcer.added == [IP, IP]             # ยิงใหม่ได้
    assert store.get_block(IP)["status"] == STATUS_ACTIVE


def test_manually_removed_can_be_blocked_again(lifecycle):
    mgr, store, enforcer, _ = lifecycle
    mgr.block(decision())
    store.set_status(IP, STATUS_MANUALLY_REMOVED)

    result = mgr.block(decision())
    assert result.success is True
    assert enforcer.added == [IP, IP]


def test_different_ip_is_not_blocked_by_guard(lifecycle):
    mgr, store, enforcer, _ = lifecycle
    mgr.block(decision(ip=IP))
    other = "203.0.113.5"
    result = mgr.block(decision(ip=other))
    assert result.success is True
    assert enforcer.added == [IP, other]
    assert len(store.get_active_blocks()) == 2


def test_failed_enforcement_leaves_no_active_block_so_retry_allowed(tmp_path):
    """enforcer ล้ม -> ไม่มี ACTIVE -> ครั้งถัดไปต้องยิงได้ (guard ไม่บล็อกเกินจำเป็น)"""
    store = BlockStore(tmp_path / "life.db")
    enforcer = FakeEnforcer(add_ok=False)
    mgr = BlockLifecycleManager(enforcer, store, clock=FakeClock(T0))

    mgr.block(decision())
    assert store.get_block(IP) is None
    mgr.block(decision())
    assert enforcer.added == [IP, IP]


# ---------- 3. pipeline: ปิดช่องว่างหลัง correlation cooldown ----------
def eve(severity=1, offset=0.0, src=IP):
    ts = (T0 + timedelta(seconds=offset)).isoformat()
    return {"src_ip": src, "dest_ip": "192.0.2.10", "severity": severity,
            "signature": "ET TEST", "signature_id": 2001219,
            "event_type": "alert", "timestamp": ts, "received_at": ts}


def build_stack(tmp_path):
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    enforcer = FakeEnforcer()
    mgr = BlockLifecycleManager(enforcer, BlockStore(db))
    pipe = SecurityPipeline(
        CorrelationEngine(window_seconds=10, min_events=5),
        RuleEngine(load_rules()), mgr,
        lock=threading.Lock(), repository=repo)
    return pipe, repo, enforcer


def rows(repo, table):
    with connect(repo.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def test_repeated_pattern_after_cooldown_does_not_reblock(tmp_path):
    """pattern ที่ 2 เกิดหลัง cooldown 10s แต่ block 300s ยัง ACTIVE
    -> ต้องไม่ยิง pfSense ซ้ำ และ expires_at ต้องไม่ขยับ"""
    pipe, repo, enforcer = build_stack(tmp_path)

    for i in range(5):                            # pattern แรก -> BLOCK
        trace = pipe.process(eve(offset=i * 0.5))
    assert trace["decision"] == BLOCK
    first_expiry = rows(repo, "active_blocks")[0]["expires_at"]
    assert enforcer.added == [IP]

    for i in range(5):                            # pattern ที่สอง (พ้น cooldown แล้ว)
        trace = pipe.process(eve(offset=20 + i * 0.5))

    assert trace["decision"] == BLOCK             # rule ยังตัดสิน BLOCK
    assert trace["duplicate_block"] is True       # แต่ถูกระงับที่ lifecycle
    assert trace["t5_enforce_ok"] is None
    assert enforcer.added == [IP]                 # ยิง pfSense ครั้งเดียวเท่านั้น
    assert rows(repo, "active_blocks")[0]["expires_at"] == first_expiry
    assert len(rows(repo, "active_blocks")) == 1


def test_duplicate_still_records_decision_but_no_extra_action(tmp_path):
    """audit: decision ที่สองยังถูกบันทึก (มันเกิดขึ้นจริง)
    แต่ไม่มี action ใหม่ เพราะไม่มีคำสั่งถูกส่งไป pfSense"""
    pipe, repo, _ = build_stack(tmp_path)
    for i in range(5):
        pipe.process(eve(offset=i * 0.5))
    for i in range(5):
        pipe.process(eve(offset=20 + i * 0.5))

    assert len(rows(repo, "decisions")) == 2      # ตัดสินสองครั้งจริง
    assert len(rows(repo, "actions")) == 1        # แต่ enforce ครั้งเดียว
    assert rows(repo, "actions")[0]["action"] == "BLOCK"


def test_active_block_action_id_unchanged_after_duplicate(tmp_path):
    pipe, repo, _ = build_stack(tmp_path)
    for i in range(5):
        pipe.process(eve(offset=i * 0.5))
    first_action_id = rows(repo, "active_blocks")[0]["action_id"]

    for i in range(5):
        pipe.process(eve(offset=20 + i * 0.5))

    assert rows(repo, "active_blocks")[0]["action_id"] == first_action_id
    assert first_action_id is not None


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
