"""
tests/test_block_remove_failed.py — STEP 6C: REMOVE_FAILED state + retry correctness

ช่องที่ปิดในรอบนี้:

    REMOVE_FAILED --block(ip)--> INSERT OR REPLACE --> ACTIVE   ❌ (สถานะ failure หาย)

ที่ต้องเป็น:

    REMOVE_FAILED --block(ip)--> ไม่ re-block, ไม่ทับ state, log --> RemovalPendingResult
    REMOVE_FAILED --retry สำเร็จ--> EXPIRED
    REMOVE_FAILED --retry ล้ม----> REMOVE_FAILED (ห้ามเป็น EXPIRED ปลอม)
    ล้มครบเพดาน --------------> หยุด retry อัตโนมัติ + log CRITICAL (สถานะคงเดิม)

ขอบเขต 6C: ไม่แตะ UNBLOCK audit และ startup reconcile (เป็น 6D)
และไม่เปลี่ยนความหมายของ DuplicateBlockResult / ACTIVE guard ของ 6A
"""
import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.correlation.engine import CorrelationEngine
from security_engine.lifecycle.block_lifecycle import (
    BlockLifecycleManager, DuplicateBlockResult, RemovalPendingResult,
    STATUS_REMOVAL_PENDING, DEFAULT_MAX_REMOVE_ATTEMPTS,
)
from security_engine.lifecycle.block_store import BlockStore
from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import Decision, RuleEngine, BLOCK
from security_engine.policy.rules_config import load_rules
from security_engine.storage.repository import AuditRepository
from security_engine.storage.schema import (
    connect, STATUS_ACTIVE, STATUS_EXPIRED, STATUS_REMOVE_FAILED,
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
    def __init__(self, add_ok=True, remove_ok=True):
        self.add_ok = add_ok
        self.remove_ok = remove_ok
        self.added = []
        self.removed = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeResult("add", ip, self.add_ok)

    def remove_block(self, ip):
        self.removed.append(ip)
        return FakeResult("remove", ip, self.remove_ok)

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


def build(tmp_path, max_remove_attempts=DEFAULT_MAX_REMOVE_ATTEMPTS):
    store = BlockStore(tmp_path / "rf.db")
    enforcer = FakeEnforcer()
    clock = FakeClock(T0)
    mgr = BlockLifecycleManager(enforcer, store, clock=clock,
                                max_remove_attempts=max_remove_attempts)
    return mgr, store, enforcer, clock


def put_into_remove_failed(mgr, store, enforcer, clock, duration=10):
    """พา block เข้าสู่สถานะ REMOVE_FAILED ตามเส้นทางจริง"""
    mgr.block(decision(duration=duration))
    clock.advance(duration + 1)
    enforcer.remove_ok = False
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED
    return mgr


# ---------- 1. block ทับ REMOVE_FAILED ไม่ได้ ----------
def test_block_on_remove_failed_does_not_call_enforcer(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)
    added_before = list(enforcer.added)

    mgr.block(decision())

    assert enforcer.added == added_before          # ไม่ยิง pfSense ใหม่


def test_block_on_remove_failed_returns_removal_pending(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)

    result = mgr.block(decision())

    assert isinstance(result, RemovalPendingResult)
    assert result.status == STATUS_REMOVAL_PENDING
    assert result.success is False
    assert result.suppressed is True
    assert result.duplicate is False               # คนละกรณีกับ 6A
    assert result.ip == IP


def test_block_on_remove_failed_keeps_status(tmp_path):
    """สถานะ failure ต้องไม่ถูกเขียนทับกลับเป็น ACTIVE"""
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)

    mgr.block(decision())

    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED
    assert store.get_active_blocks() == []


def test_block_on_remove_failed_does_not_touch_timestamps(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)
    before = store.get_block(IP)

    clock.advance(120)
    mgr.block(decision())
    after = store.get_block(IP)

    assert after["blocked_at"] == before["blocked_at"]
    assert after["expires_at"] == before["expires_at"]


def test_block_on_remove_failed_is_logged(tmp_path, caplog):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)

    with caplog.at_level(logging.WARNING):
        mgr.block(decision())

    assert any("REMOVE_FAILED" in r.message for r in caplog.records)


def test_still_findable_for_retry_after_block_attempt(tmp_path):
    """หลังพยายาม block ทับ ตัวนั้นต้องยัง retry ได้อยู่"""
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)
    mgr.block(decision())

    assert [b["src_ip"] for b in store.get_blocks_by_status(STATUS_REMOVE_FAILED)] == [IP]
    enforcer.remove_ok = True
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


# ---------- 2. retry semantics ----------
def test_retry_success_moves_to_expired(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)

    enforcer.remove_ok = True
    mgr.expire_due()

    assert store.get_block(IP)["status"] == STATUS_EXPIRED
    assert mgr.removal_attempts(IP) == 0           # counter ถูกล้างเมื่อสำเร็จ


def test_retry_failure_stays_remove_failed(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)

    mgr.expire_due()                               # retry แต่ยังล้ม

    status = store.get_block(IP)["status"]
    assert status == STATUS_REMOVE_FAILED
    assert status != STATUS_EXPIRED                # ห้ามสร้าง EXPIRED ปลอม


def test_attempts_are_counted(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path, max_remove_attempts=5)
    put_into_remove_failed(mgr, store, enforcer, clock)
    assert mgr.removal_attempts(IP) == 1

    mgr.expire_due()
    mgr.expire_due()
    assert mgr.removal_attempts(IP) == 3


def test_retry_stops_after_max_attempts(tmp_path):
    """ไม่ retry ไม่รู้จบ — ครบเพดานแล้วหยุดเรียก enforcer"""
    mgr, store, enforcer, clock = build(tmp_path, max_remove_attempts=3)
    put_into_remove_failed(mgr, store, enforcer, clock)   # attempt 1

    mgr.expire_due()                                      # attempt 2
    mgr.expire_due()                                      # attempt 3 -> ครบเพดาน
    calls_at_cap = len(enforcer.removed)
    assert mgr.is_removal_exhausted(IP) is True

    for _ in range(10):                                   # เรียกอีกกี่รอบก็ไม่ยิงแล้ว
        mgr.expire_due()

    assert len(enforcer.removed) == calls_at_cap
    assert mgr.removal_attempts(IP) == 3


def test_exhausted_block_keeps_remove_failed_status(tmp_path):
    """หยุด retry แล้วต้องยังเห็นว่าค้างอยู่ ไม่ใช่หายไปเงียบ ๆ"""
    mgr, store, enforcer, clock = build(tmp_path, max_remove_attempts=2)
    put_into_remove_failed(mgr, store, enforcer, clock)
    mgr.expire_due()
    for _ in range(5):
        mgr.expire_due()

    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED
    assert [b["src_ip"] for b in store.get_blocks_by_status(STATUS_REMOVE_FAILED)] == [IP]


def test_exhaustion_is_logged_as_critical(tmp_path, caplog):
    mgr, store, enforcer, clock = build(tmp_path, max_remove_attempts=2)
    put_into_remove_failed(mgr, store, enforcer, clock)

    with caplog.at_level(logging.CRITICAL):
        mgr.expire_due()                                  # attempt 2 -> ครบเพดาน

    assert any(r.levelname == "CRITICAL" for r in caplog.records)


def test_each_failure_is_logged_as_error(tmp_path, caplog):
    """NFR-06: ปลดไม่สำเร็จต้อง ALERT ทันที ไม่ใช่รอครบเพดาน"""
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10))
    clock.advance(11)
    enforcer.remove_ok = False

    with caplog.at_level(logging.ERROR):
        mgr.expire_due()

    assert any(r.levelname == "ERROR" for r in caplog.records)


def test_exhausted_counter_resets_after_successful_removal(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path, max_remove_attempts=2)
    put_into_remove_failed(mgr, store, enforcer, clock)
    enforcer.remove_ok = True
    mgr.expire_due()

    assert mgr.is_removal_exhausted(IP) is False
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


def test_other_ip_not_affected_by_exhaustion(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path, max_remove_attempts=1)
    other = "203.0.113.5"
    put_into_remove_failed(mgr, store, enforcer, clock)   # IP ค้างและ exhausted

    enforcer.remove_ok = True
    mgr.block(decision(duration=10, ip=other))
    clock.advance(11)
    mgr.expire_due()

    assert store.get_block(other)["status"] == STATUS_EXPIRED
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED


# ---------- 3. block ได้อีกครั้งหลังปลดสำเร็จ ----------
def test_block_allowed_again_after_retry_succeeds(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    put_into_remove_failed(mgr, store, enforcer, clock)
    enforcer.remove_ok = True
    mgr.expire_due()                                      # -> EXPIRED

    result = mgr.block(decision())

    assert result.success is True
    assert store.get_block(IP)["status"] == STATUS_ACTIVE


# ---------- 4. ไม่กระทบ 6A / 6B ----------
def test_duplicate_guard_unchanged(tmp_path):
    mgr, store, enforcer, _ = build(tmp_path)
    mgr.block(decision())
    result = mgr.block(decision())
    assert isinstance(result, DuplicateBlockResult)
    assert result.duplicate is True
    assert enforcer.added == [IP]


def test_normal_expiry_path_unchanged(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


# ---------- 5. pipeline: ไม่สร้าง action ปลอมตอน suppressed ----------
def eve(severity=1, offset=0.0, src=IP):
    ts = (T0 + timedelta(seconds=offset)).isoformat()
    return {"src_ip": src, "dest_ip": "192.0.2.10", "severity": severity,
            "signature": "ET TEST", "signature_id": 2001219,
            "event_type": "alert", "timestamp": ts, "received_at": ts}


def rows(repo, table):
    with connect(repo.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def test_pipeline_records_no_action_when_removal_pending(tmp_path):
    """pattern ใหม่ระหว่างที่ IP ค้าง REMOVE_FAILED -> decision ถูกบันทึก
    แต่ไม่มี action เพราะไม่มีคำสั่งถูกส่งไป pfSense"""
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    store = BlockStore(db)
    enforcer = FakeEnforcer()
    clock = FakeClock(T0)
    mgr = BlockLifecycleManager(enforcer, store, clock=clock)
    pipe = SecurityPipeline(CorrelationEngine(window_seconds=10, min_events=5),
                            RuleEngine(load_rules()), mgr,
                            lock=threading.Lock(), repository=repo)

    put_into_remove_failed(mgr, store, enforcer, clock)
    actions_before = len(rows(repo, "actions"))

    for i in range(5):
        trace = pipe.process(eve(offset=100 + i * 0.5))

    assert trace["decision"] == BLOCK
    assert trace["block_suppressed"] is True
    assert trace["duplicate_block"] is False          # ไม่ใช่เคส duplicate ACTIVE
    assert trace["t5_enforce_ok"] is None
    assert len(rows(repo, "actions")) == actions_before
    assert len(rows(repo, "decisions")) == 1          # decision ยังถูกบันทึกตามจริง
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
