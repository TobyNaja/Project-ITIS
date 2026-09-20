"""
tests/test_pfsense_integration.py — Phase 8 Integration Test (ยิง pfSense จริง)

*** ไม่รันโดย default ***
test ชุดนี้แก้ table ITIS_BLOCK_TEST บน pfSense จริง จึงถูก skip
จนกว่าจะตั้ง environment variable:

    PowerShell:
        $env:ITIS_PFSENSE_HOST = "admin@192.168.227.150"
        python -m pytest tests/test_pfsense_integration.py -v

    bash:
        ITIS_PFSENSE_HOST=admin@192.168.227.150 python -m pytest tests/test_pfsense_integration.py -v

ใช้ IP ทดสอบจาก TEST-NET-2 (198.51.100.0/24, RFC 5737) ซึ่งไม่มีเครื่องจริงในแลป
-> block แล้วไม่กระทบ traffic ของ Kali/SEC01 ระหว่างรัน test
ทุก test ล้าง IP ทดสอบออกจาก table ใน teardown เสมอ แม้ test จะ fail
"""
import os

import pytest

from security_engine.enforcement.pfsense_enforcer import (
    PFSenseEnforcer, EnforcementError,
)

HOST = os.environ.get("ITIS_PFSENSE_HOST")
TEST_IP = "198.51.100.77"

pytestmark = pytest.mark.skipif(
    not HOST,
    reason="ตั้ง ITIS_PFSENSE_HOST ก่อนถึงจะยิง pfSense จริง",
)


@pytest.fixture
def enforcer():
    e = PFSenseEnforcer(HOST)
    # precondition: IP ทดสอบต้องไม่อยู่ใน table ก่อนเริ่ม
    if e.is_blocked(TEST_IP):
        e.remove_block(TEST_IP)
    assert not e.is_blocked(TEST_IP)
    yield e
    # teardown: ล้างเสมอ ไม่ทิ้ง state ค้างบน pfSense
    if e.is_blocked(TEST_IP):
        e.remove_block(TEST_IP)


def test_read_table(enforcer):
    ips = enforcer.get_blocked_ips()
    assert isinstance(ips, set)


def test_add_block_enforced_and_verified(enforcer):
    r = enforcer.add_block(TEST_IP)
    assert r.command_ok
    assert r.verified
    assert r.status == "ENFORCED"
    # ยืนยันซ้ำด้วย read-back แยกอีกรอบ
    assert enforcer.is_blocked(TEST_IP)


def test_remove_block_removed_and_verified(enforcer):
    enforcer.add_block(TEST_IP)
    r = enforcer.remove_block(TEST_IP)
    assert r.command_ok
    assert r.verified
    assert r.status == "REMOVED"
    assert not enforcer.is_blocked(TEST_IP)


def test_duplicate_add_is_idempotent(enforcer):
    assert enforcer.add_block(TEST_IP).status == "ENFORCED"
    assert enforcer.add_block(TEST_IP).status == "ENFORCED"
    assert enforcer.is_blocked(TEST_IP)


def test_duplicate_remove_is_idempotent(enforcer):
    enforcer.add_block(TEST_IP)
    assert enforcer.remove_block(TEST_IP).status == "REMOVED"
    assert enforcer.remove_block(TEST_IP).status == "REMOVED"
    assert not enforcer.is_blocked(TEST_IP)


def test_other_ips_untouched(enforcer):
    # add/remove IP ทดสอบต้องไม่แตะ IP อื่นที่อยู่ใน table
    before = enforcer.get_blocked_ips() - {TEST_IP}
    enforcer.add_block(TEST_IP)
    enforcer.remove_block(TEST_IP)
    after = enforcer.get_blocked_ips() - {TEST_IP}
    assert before == after


def test_invalid_ip_rejected_before_ssh(enforcer):
    with pytest.raises(EnforcementError):
        enforcer.add_block("999.999.999.999")