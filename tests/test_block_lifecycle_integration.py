"""
tests/test_block_lifecycle_integration.py — Phase 9.2d

Real integration: BlockLifecycleManager + PFSenseEnforcer จริง + pfSense จริง
พิสูจน์ lifecycle เต็ม: Decision(BLOCK) → add ที่ pfSense → ACTIVE → หมดอายุ →
expire_due() → remove ที่ pfSense → EXPIRED → IP หายจาก table จริง

*** ไม่รันโดย default *** — ต้องตั้ง env:
    PowerShell:
        $env:ITIS_PFSENSE_HOST = "admin@192.168.227.150"
        python -m pytest tests/test_block_lifecycle_integration.py -v
    bash:
        ITIS_PFSENSE_HOST=admin@192.168.227.150 python -m pytest ... -v

ใช้ IP ทดสอบ 198.51.100.77 (TEST-NET, ไม่ใช่ Kali) -> พลาดก็ไม่ตัด connectivity จริง
มี teardown ล้าง IP ออกจาก pfSense table เสมอ แม้ test fail
"""
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.enforcement.pfsense_enforcer import PFSenseEnforcer
from security_engine.lifecycle.block_store import BlockStore
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
from security_engine.policy.rule_engine import Decision, BLOCK

HOST = os.environ.get("ITIS_PFSENSE_HOST")
TEST_IP = "198.51.100.77"

pytestmark = pytest.mark.skipif(
    not HOST, reason="ตั้ง ITIS_PFSENSE_HOST ก่อนถึงจะยิง pfSense จริง"
)


class FakeClock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t = self.t + timedelta(seconds=seconds)


def _decision(duration):
    return Decision(action=BLOCK, rule_id="RULE-001", src_ip=TEST_IP,
                    reason="phase9.2d integration", block_duration=duration)


@pytest.fixture
def setup(tmp_path):
    enforcer = PFSenseEnforcer(HOST)
    store = BlockStore(tmp_path / "life.db")
    # precondition: IP ทดสอบต้องไม่อยู่ใน pfSense table
    if enforcer.is_blocked(TEST_IP):
        enforcer.remove_block(TEST_IP)
    assert not enforcer.is_blocked(TEST_IP)
    yield enforcer, store
    # teardown: ล้าง IP ออกจาก pfSense เสมอ ไม่ทิ้ง state ค้าง
    if enforcer.is_blocked(TEST_IP):
        enforcer.remove_block(TEST_IP)


def test_full_lifecycle_with_clock_advance(setup):
    """เคสหลัก: block ที่ pfSense จริง แล้ว advance clock ข้ามเวลา -> auto-unblock
    (enforcement จริง, เวลา deterministic -> เร็ว ไม่ flaky)"""
    enforcer, store = setup
    clock = FakeClock(datetime.now(timezone.utc))
    mgr = BlockLifecycleManager(enforcer, store, clock=clock)

    # 1) block -> ต้องอยู่ใน pfSense table จริง + ACTIVE
    result = mgr.block(_decision(duration=300))
    assert result.success
    assert enforcer.is_blocked(TEST_IP)                  # อยู่ใน table จริง
    assert store.get_block(TEST_IP)["status"] == "ACTIVE"

    # 2) ยังไม่หมดอายุ -> expire ไม่แตะ
    clock.advance(100)
    mgr.expire_due()
    assert enforcer.is_blocked(TEST_IP)                  # ยัง block อยู่
    assert store.get_block(TEST_IP)["status"] == "ACTIVE"

    # 3) เลยหมดอายุ -> expire_due -> remove จาก pfSense จริง + EXPIRED
    clock.advance(250)                                   # รวม 350 > 300
    mgr.expire_due()
    assert not enforcer.is_blocked(TEST_IP)              # หายจาก table จริง
    assert store.get_block(TEST_IP)["status"] == "EXPIRED"


def test_full_lifecycle_real_time_short_duration(setup):
    """เคสยืนยันเวลาจริง: duration 5s + sleep จริง -> auto-unblock
    (ช้ากว่าแต่พิสูจน์ว่าเวลานาฬิกาจริงก็ทำงาน ไม่ใช่แค่ clock ปลอม)"""
    enforcer, store = setup
    mgr = BlockLifecycleManager(enforcer, store)         # ใช้ clock จริง

    mgr.block(_decision(duration=5))
    assert enforcer.is_blocked(TEST_IP)

    # ก่อนหมดอายุ
    mgr.expire_due()
    assert enforcer.is_blocked(TEST_IP)                  # 5s ยังไม่ผ่าน

    time.sleep(6)                                        # รอเลย 5s
    mgr.expire_due()
    assert not enforcer.is_blocked(TEST_IP)              # auto-unblock จริง
    assert store.get_block(TEST_IP)["status"] == "EXPIRED"


def test_reconcile_after_restart_real(setup):
    """restart จริง: Manager ตัวใหม่ + DB เดิม -> reconcile ปลด block ที่ค้างบน pfSense"""
    enforcer, store = setup
    clock = FakeClock(datetime.now(timezone.utc))

    # Manager #1 block ไว้
    mgr1 = BlockLifecycleManager(enforcer, store, clock=clock)
    mgr1.block(_decision(duration=300))
    assert enforcer.is_blocked(TEST_IP)

    # ...process ดับ... เวลาผ่านไปเกินหมดอายุ
    clock.advance(400)

    # Manager #2 (instance ใหม่, DB path เดิม) -> reconcile
    store2 = BlockStore(store.db_path)
    mgr2 = BlockLifecycleManager(enforcer, store2, clock=clock)
    mgr2.reconcile()

    assert not enforcer.is_blocked(TEST_IP)              # ปลดจาก pfSense จริง
    assert store2.get_block(TEST_IP)["status"] == "EXPIRED"