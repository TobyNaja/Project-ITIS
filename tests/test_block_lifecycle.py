"""
tests/test_block_lifecycle.py — Phase 9.2c

ทดสอบ BlockLifecycleManager ด้วย FakeEnforcer + FakeClock + BlockStore จริง (tmp SQLite)
ไม่ยิง SSH/pfSense — แต่ตรวจ flow จริงของ Manager + Store

ครอบ 12 เคสตามที่ล็อก (จุดเสี่ยง lifecycle: #2 no-fake-ACTIVE, #8 REMOVE_FAILED,
#9 retry, #11 reconcile หลัง restart)
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.lifecycle.block_store import BlockStore
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
from security_engine.policy.rule_engine import Decision, BLOCK, MONITOR


# ---- fakes ----

class FakeResult:
    def __init__(self, success):
        self.success = success


class FakeEnforcer:
    """คุม success ของ add/remove ได้ + บันทึกว่าถูกเรียกอะไรบ้าง"""
    def __init__(self, add_ok=True, remove_ok=True):
        self.add_ok = add_ok
        self.remove_ok = remove_ok
        self.added = []
        self.removed = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeResult(self.add_ok)

    def remove_block(self, ip):
        self.removed.append(ip)
        return FakeResult(self.remove_ok)


class FakeClock:
    """เวลาเดินเองไม่ได้ — เราขยับด้วยมือ ไม่ต้องรอ 300s จริง"""
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t = self.t + timedelta(seconds=seconds)


T0 = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
IP = "192.168.2.10"


def make_decision(action=BLOCK, ip=IP, duration=300, rule_id="RULE-001", reason="HIGH"):
    return Decision(action=action, rule_id=rule_id, src_ip=ip,
                    reason=reason, block_duration=duration)


@pytest.fixture
def setup(tmp_path):
    store = BlockStore(tmp_path / "life.db")
    clock = FakeClock(T0)
    return store, clock


# ---- 1. block สำเร็จ ----
def test_block_success_creates_active(setup):
    store, clock = setup
    enf = FakeEnforcer(add_ok=True)
    mgr = BlockLifecycleManager(enf, store, clock=clock)

    mgr.block(make_decision())

    assert enf.added == [IP]
    blk = store.get_block(IP)
    assert blk["status"] == "ACTIVE"


# ---- 2. block fail -> ห้ามสร้าง ACTIVE ----
def test_block_fail_does_not_create_active(setup):
    store, clock = setup
    enf = FakeEnforcer(add_ok=False)      # pfSense verify ไม่ผ่าน
    mgr = BlockLifecycleManager(enf, store, clock=clock)

    mgr.block(make_decision())

    assert enf.added == [IP]               # พยายาม add แล้ว
    assert store.get_block(IP) is None      # แต่ไม่มี record ปลอมใน DB


# ---- 3. expires_at = now + duration ----
def test_expires_at_is_now_plus_duration(setup):
    store, clock = setup
    mgr = BlockLifecycleManager(FakeEnforcer(), store, clock=clock)

    mgr.block(make_decision(duration=300))

    blk = store.get_block(IP)
    expected = (T0 + timedelta(seconds=300)).isoformat()
    assert blk["expires_at"] == expected
    assert blk["blocked_at"] == T0.isoformat()


# ---- 4. custom duration (60 ไม่ใช่ 300) ----
def test_custom_duration_from_decision(setup):
    store, clock = setup
    mgr = BlockLifecycleManager(FakeEnforcer(), store, clock=clock)

    mgr.block(make_decision(duration=60))

    blk = store.get_block(IP)
    assert blk["expires_at"] == (T0 + timedelta(seconds=60)).isoformat()


# ---- 5. expire -> remove -> UNBLOCKED ----
def test_expire_due_removes_expired(setup):
    store, clock = setup
    enf = FakeEnforcer(remove_ok=True)
    mgr = BlockLifecycleManager(enf, store, clock=clock)
    mgr.block(make_decision(duration=300))

    clock.advance(301)                     # เลยหมดอายุ
    mgr.expire_due()

    assert enf.removed == [IP]
    assert store.get_block(IP)["status"] == "UNBLOCKED"


# ---- 6. unexpired -> ไม่ remove ----
def test_unexpired_not_removed(setup):
    store, clock = setup
    enf = FakeEnforcer()
    mgr = BlockLifecycleManager(enf, store, clock=clock)
    mgr.block(make_decision(duration=300))

    clock.advance(100)                     # ยังไม่หมด
    mgr.expire_due()

    assert enf.removed == []
    assert store.get_block(IP)["status"] == "ACTIVE"


# ---- 7. remove success -> UNBLOCKED ----
def test_remove_success_unblocked(setup):
    store, clock = setup
    enf = FakeEnforcer(remove_ok=True)
    mgr = BlockLifecycleManager(enf, store, clock=clock)
    mgr.block(make_decision(duration=300))
    clock.advance(301)

    mgr.expire_due()

    assert store.get_block(IP)["status"] == "UNBLOCKED"


# ---- 8. remove fail -> REMOVE_FAILED ----
def test_remove_fail_marks_remove_failed(setup):
    store, clock = setup
    enf = FakeEnforcer(remove_ok=False)    # unblock verify ไม่ผ่าน
    mgr = BlockLifecycleManager(enf, store, clock=clock)
    mgr.block(make_decision(duration=300))
    clock.advance(301)

    mgr.expire_due()

    assert store.get_block(IP)["status"] == "REMOVE_FAILED"


# ---- 9. retry success -> UNBLOCKED ----
def test_retry_success_unblocks(setup):
    store, clock = setup
    enf = FakeEnforcer(remove_ok=False)
    mgr = BlockLifecycleManager(enf, store, clock=clock)
    mgr.block(make_decision(duration=300))
    clock.advance(301)
    mgr.expire_due()                       # รอบแรก fail -> REMOVE_FAILED
    assert store.get_block(IP)["status"] == "REMOVE_FAILED"

    enf.remove_ok = True                   # pfSense กลับมาปกติ
    mgr.expire_due()                       # retry

    assert store.get_block(IP)["status"] == "UNBLOCKED"


# ---- 10. retry fail -> ยังคง REMOVE_FAILED ----
def test_retry_still_fails_stays_remove_failed(setup):
    store, clock = setup
    enf = FakeEnforcer(remove_ok=False)
    mgr = BlockLifecycleManager(enf, store, clock=clock)
    mgr.block(make_decision(duration=300))
    clock.advance(301)
    mgr.expire_due()
    mgr.expire_due()                       # retry แต่ยัง fail

    assert store.get_block(IP)["status"] == "REMOVE_FAILED"


# ---- 11. reconcile หลัง restart: Manager ตัวใหม่อ่าน SQLite ----
def test_reconcile_after_restart_removes_expired(tmp_path):
    db = tmp_path / "life.db"
    clock = FakeClock(T0)

    # Manager ตัวที่ 1: block ไว้
    store1 = BlockStore(db)
    enf1 = FakeEnforcer()
    mgr1 = BlockLifecycleManager(enf1, store1, clock=clock)
    mgr1.block(make_decision(duration=300))

    # ...process ดับ... เวลาผ่านไปเกินหมดอายุ
    clock.advance(301)

    # Manager ตัวที่ 2 (instance ใหม่, DB เดิม) — state ต้องมาจาก SQLite ไม่ใช่ memory
    store2 = BlockStore(db)
    enf2 = FakeEnforcer(remove_ok=True)
    mgr2 = BlockLifecycleManager(enf2, store2, clock=clock)
    mgr2.reconcile()

    assert enf2.removed == [IP]            # Manager ใหม่ปลด block ที่ค้าง
    assert store2.get_block(IP)["status"] == "UNBLOCKED"


# ---- 12. non-BLOCK -> ValueError, ไม่แตะ enforcer ----
def test_non_block_decision_rejected(setup):
    store, clock = setup
    enf = FakeEnforcer()
    mgr = BlockLifecycleManager(enf, store, clock=clock)

    with pytest.raises(ValueError):
        mgr.block(make_decision(action=MONITOR, rule_id="DEFAULT"))

    assert enf.added == []                 # ไม่มีการสั่ง pfSense เลย
    assert store.get_block(IP) is None