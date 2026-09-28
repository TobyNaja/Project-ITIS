"""
tests/test_block_expiry.py — STEP 6B: expiry correctness + state transitions

state machine ที่ต้องถูกต้อง (FR-09 + NFR-06 + §3.4):

    ACTIVE --หมดอายุ + remove สำเร็จ (command OK + verify OK)--> EXPIRED
    ACTIVE --หมดอายุ + remove ล้ม (command หรือ verify ล้ม)----> REMOVE_FAILED
    ACTIVE --ยังไม่หมดอายุ------------------------------------> ACTIVE (ไม่แตะ)

*** ความล้มเหลวห้ามถูกเขียนเป็น EXPIRED *** — ถ้าปลดไม่สำเร็จแล้วบอกว่า EXPIRED
ระบบจะ "ลืม" block ที่ยังค้างอยู่บน pfSense (ขัด NFR-06 ที่ว่าค้าง block อันตรายกว่า)

ขอบเขต 6B: การเปลี่ยนสถานะตอนหมดอายุเท่านั้น
    - retry ของ REMOVE_FAILED = 6C
    - startup reconcile = 6D
    - ไม่แตะ ACTIVE guard / DuplicateBlockResult ของ 6A
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.lifecycle.block_lifecycle import (
    BlockLifecycleManager, DuplicateBlockResult,
)
from security_engine.lifecycle.block_store import BlockStore
from security_engine.policy.rule_engine import Decision, BLOCK
from security_engine.storage.schema import (
    STATUS_ACTIVE, STATUS_EXPIRED, STATUS_REMOVE_FAILED,
)

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
IP = "198.51.100.77"
OTHER = "203.0.113.5"


class FakeResult:
    def __init__(self, action, ip, command_ok=True, verified=True):
        self.action = action
        self.ip = ip
        self.command_ok = command_ok
        self.verified = verified
        self.status = ("ENFORCED" if action == "add" else "REMOVED") \
            if command_ok and verified else "FAILED"

    @property
    def success(self):
        return self.command_ok and self.verified


class FakeEnforcer:
    """คุมผลของ add/remove แยกกันได้ (command กับ verify แยกกันตาม FR-08)"""
    def __init__(self, add_ok=True, remove_command_ok=True, remove_verified=True):
        self.add_ok = add_ok
        self.remove_command_ok = remove_command_ok
        self.remove_verified = remove_verified
        self.added = []
        self.removed = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeResult("add", ip, self.add_ok, self.add_ok)

    def remove_block(self, ip):
        self.removed.append(ip)
        return FakeResult("remove", ip, self.remove_command_ok, self.remove_verified)

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


def build(tmp_path, **enforcer_kwargs):
    store = BlockStore(tmp_path / "expiry.db")
    enforcer = FakeEnforcer(**enforcer_kwargs)
    clock = FakeClock(T0)
    return BlockLifecycleManager(enforcer, store, clock=clock), store, enforcer, clock


# ---------- 1. ACTIVE -> EXPIRED (เส้นทางสำเร็จ) ----------
def test_expired_block_becomes_expired(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=300))
    clock.advance(301)

    processed = mgr.expire_due()

    assert enforcer.removed == [IP]
    assert store.get_block(IP)["status"] == STATUS_EXPIRED
    assert [ip for ip, _ in processed] == [IP]
    assert processed[0][1].success is True


def test_expired_block_is_not_active_anymore(tmp_path):
    mgr, store, _, clock = build(tmp_path)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()
    assert store.get_active_blocks() == []


def test_expiry_at_exact_boundary(tmp_path):
    """expires_at == now ต้องถือว่าหมดอายุแล้ว (เกณฑ์ <=)"""
    mgr, store, _, clock = build(tmp_path)
    mgr.block(decision(duration=300))
    clock.advance(300)                       # ตรงเป๊ะ
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


def test_one_second_before_expiry_stays_active(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=300))
    clock.advance(299)
    mgr.expire_due()

    assert enforcer.removed == []
    assert store.get_block(IP)["status"] == STATUS_ACTIVE


def test_expire_due_with_explicit_now(tmp_path):
    mgr, store, _, _ = build(tmp_path)
    mgr.block(decision(duration=300))
    mgr.expire_due(now=T0 + timedelta(seconds=400))
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


# ---------- 2. ACTIVE -> REMOVE_FAILED (ห้ามเขียนเป็น EXPIRED) ----------
def test_remove_command_failure_becomes_remove_failed(tmp_path):
    mgr, store, _, clock = build(tmp_path, remove_command_ok=False)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()

    status = store.get_block(IP)["status"]
    assert status == STATUS_REMOVE_FAILED
    assert status != STATUS_EXPIRED          # ห้ามบอกว่าปลดแล้วทั้งที่ไม่ได้ปลด


def test_verify_failure_becomes_remove_failed(tmp_path):
    """command สำเร็จแต่ read-back บอกว่า IP ยังอยู่ -> ยังไม่ปลด (FR-08)"""
    mgr, store, _, clock = build(tmp_path, remove_verified=False)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED


def test_failed_removal_is_not_counted_as_active(tmp_path):
    """REMOVE_FAILED ต้องไม่ถูกนับเป็น ACTIVE (จะได้ไม่ re-block ซ้ำ)"""
    mgr, store, _, clock = build(tmp_path, remove_command_ok=False)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()
    assert store.get_active_blocks() == []
    assert [b["src_ip"] for b in store.get_blocks_by_status(STATUS_REMOVE_FAILED)] == [IP]


def test_failed_removal_returns_unsuccessful_result(tmp_path):
    mgr, _, _, clock = build(tmp_path, remove_command_ok=False)
    mgr.block(decision(duration=10))
    clock.advance(11)
    processed = mgr.expire_due()
    assert processed[0][1].success is False


def test_expired_row_is_never_reprocessed(tmp_path):
    """EXPIRED แล้วต้องไม่ถูกหยิบมาปลดซ้ำในรอบถัดไป"""
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()
    mgr.expire_due()
    mgr.expire_due()
    assert enforcer.removed == [IP]           # ปลดครั้งเดียว


# ---------- 3. หลาย IP พร้อมกัน ----------
def test_only_expired_ips_are_removed(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10, ip=IP))
    mgr.block(decision(duration=600, ip=OTHER))
    clock.advance(11)

    mgr.expire_due()

    assert enforcer.removed == [IP]
    assert store.get_block(IP)["status"] == STATUS_EXPIRED
    assert store.get_block(OTHER)["status"] == STATUS_ACTIVE


def test_multiple_expired_blocks_all_processed(tmp_path):
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10, ip=IP))
    mgr.block(decision(duration=10, ip=OTHER))
    clock.advance(11)

    processed = mgr.expire_due()

    assert sorted(enforcer.removed) == sorted([IP, OTHER])
    assert len(processed) == 2
    assert store.get_block(IP)["status"] == STATUS_EXPIRED
    assert store.get_block(OTHER)["status"] == STATUS_EXPIRED


def test_one_failure_does_not_block_the_other(tmp_path):
    """IP หนึ่งปลดไม่สำเร็จ ต้องไม่ทำให้ IP อื่นค้าง"""
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10, ip=IP))
    mgr.block(decision(duration=10, ip=OTHER))
    clock.advance(11)

    original_remove = enforcer.remove_block

    def flaky_remove(ip):
        result = original_remove(ip)
        if ip == IP:
            return FakeResult("remove", ip, command_ok=False, verified=False)
        return result

    enforcer.remove_block = flaky_remove
    mgr.expire_due()

    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED
    assert store.get_block(OTHER)["status"] == STATUS_EXPIRED


# ---------- 4. นาฬิกา / timezone ----------
def test_expiry_uses_injected_clock_not_wall_time(tmp_path):
    mgr, store, _, clock = build(tmp_path)
    mgr.block(decision(duration=300))
    mgr.expire_due()                          # clock ยังไม่เดิน
    assert store.get_block(IP)["status"] == STATUS_ACTIVE
    clock.advance(301)
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


def test_expiry_compares_across_timezone_offsets(tmp_path):
    """เทียบเวลาด้วย datetime จริง ไม่ใช่ string (offset ต่างกันต้องยังถูก)"""
    store = BlockStore(tmp_path / "tz.db")
    blocked_at = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
    expires_at = blocked_at + timedelta(seconds=300)
    bangkok = timezone(timedelta(hours=7))
    store.add_block(IP, blocked_at.isoformat(),
                    expires_at.astimezone(bangkok).isoformat())

    expired = store.get_expired_blocks(expires_at + timedelta(seconds=1))
    assert [b["src_ip"] for b in expired] == [IP]


# ---------- 5. ไม่กระทบสิ่งที่ 6A ล็อกไว้ ----------
def test_duplicate_guard_still_active_after_expiry_changes(tmp_path):
    mgr, store, enforcer, _ = build(tmp_path)
    mgr.block(decision())
    result = mgr.block(decision())
    assert isinstance(result, DuplicateBlockResult)
    assert enforcer.added == [IP]


def test_block_again_after_expired_is_allowed(tmp_path):
    """EXPIRED -> block ใหม่ได้ และ expires_at ต้องเป็นรอบใหม่จริง"""
    mgr, store, enforcer, clock = build(tmp_path)
    mgr.block(decision(duration=10))
    clock.advance(11)
    mgr.expire_due()
    first_expiry = store.get_block(IP)["expires_at"]

    mgr.block(decision(duration=300))
    second = store.get_block(IP)

    assert second["status"] == STATUS_ACTIVE
    assert second["expires_at"] != first_expiry
    assert enforcer.added == [IP, IP]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
