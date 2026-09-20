"""
tests/test_pfsense_enforcer.py — Phase 8 Unit Test (mock SSH)

ไม่ยิง pfSense จริง — mock ที่ชั้น _run (SSH layer) เท่านั้น
ครอบคลุม 10 เคสตามแผน 8.11:
  1 add success            6 invalid IP
  2 add verify success     7 duplicate add
  3 add verify FAILURE     8 duplicate remove
  4 remove success         9 SSH failure
  5 remove verify success  10 pfctl failure
"""
import unittest
from unittest.mock import patch

from security_engine.enforcement.pfsense_enforcer import (
    PFSenseEnforcer, EnforcementError, validate_ip,
)

HOST = "admin@192.168.227.150"
IP = "192.168.2.10"


def _show(ips):
    """จำลอง output ของ pfctl -T show"""
    return "\n".join(f"   {i}" for i in ips) + ("\n" if ips else "")


class TestValidateIP(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(validate_ip("192.168.2.10"), "192.168.2.10")

    def test_valid_ipv6(self):
        self.assertEqual(validate_ip("::1"), "::1")

    def test_invalid_raises(self):        # เคส 6
        with self.assertRaises(EnforcementError):
            validate_ip("999.999.999.999")

    def test_garbage_raises(self):
        with self.assertRaises(EnforcementError):
            validate_ip("; rm -rf /")     # กัน injection


class TestAdd(unittest.TestCase):
    def setUp(self):
        self.eng = PFSenseEnforcer(HOST)

    def test_add_success_and_verify(self):    # เคส 1 + 2
        # add rc=0 แล้ว read-back เจอ IP
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [
                (0, ""),              # add
                (0, _show([IP])),     # show (read-back)
            ]
            r = self.eng.add_block(IP)
        self.assertTrue(r.command_ok)
        self.assertTrue(r.verified)
        self.assertTrue(r.success)
        self.assertEqual(r.status, "ENFORCED")

    def test_add_command_ok_but_verify_fails(self):   # เคส 3 (สำคัญสุด)
        # command บอกสำเร็จ (rc=0) แต่ read-back ไม่เจอ IP -> ต้อง FAILED
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [
                (0, ""),              # add rc=0
                (0, _show([])),       # show ว่าง — ไม่เจอ IP
            ]
            r = self.eng.add_block(IP)
        self.assertTrue(r.command_ok)
        self.assertFalse(r.verified)
        self.assertFalse(r.success)
        self.assertEqual(r.status, "FAILED")

    def test_add_invalid_ip_never_calls_ssh(self):    # เคส 6
        with patch.object(self.eng, "_run") as m:
            with self.assertRaises(EnforcementError):
                self.eng.add_block("999.999.999.999")
            m.assert_not_called()      # ต้องไม่ส่ง command ไป pfSense

    def test_duplicate_add_does_not_crash(self):      # เคส 7
        # add IP ที่มีอยู่แล้ว — pfctl rc=0, read-back ยังเจอ -> ENFORCED
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [(0, ""), (0, _show([IP]))]
            r = self.eng.add_block(IP)
        self.assertEqual(r.status, "ENFORCED")


class TestRemove(unittest.TestCase):
    def setUp(self):
        self.eng = PFSenseEnforcer(HOST)

    def test_remove_success_and_verify(self):     # เคส 4 + 5
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [
                (0, ""),              # delete
                (0, _show([])),       # show — หายแล้ว
            ]
            r = self.eng.remove_block(IP)
        self.assertTrue(r.success)
        self.assertEqual(r.status, "REMOVED")

    def test_remove_verify_fails(self):
        # delete rc=0 แต่ IP ยังอยู่ -> FAILED
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [(0, ""), (0, _show([IP]))]
            r = self.eng.remove_block(IP)
        self.assertFalse(r.success)
        self.assertEqual(r.status, "FAILED")

    def test_duplicate_remove_does_not_crash(self):   # เคส 8
        # remove IP ที่ไม่มีอยู่ — pfctl rc=0, read-back ว่าง -> REMOVED
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [(0, ""), (0, _show([]))]
            r = self.eng.remove_block(IP)
        self.assertEqual(r.status, "REMOVED")


class TestFailures(unittest.TestCase):
    def setUp(self):
        self.eng = PFSenseEnforcer(HOST)

    def test_ssh_failure_raises(self):        # เคส 9
        import subprocess
        with patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired("ssh", 5)):
            with self.assertRaises(EnforcementError):
                self.eng.add_block(IP)

    def test_pfctl_show_failure_raises(self):     # เคส 10
        # pfctl show rc!=0 -> EnforcementError
        with patch.object(self.eng, "_run", return_value=(1, "")):
            with self.assertRaises(EnforcementError):
                self.eng.get_blocked_ips()

    def test_add_then_pfctl_show_fails(self):
        # add rc=0 แต่ read-back (show) พัง rc=1 -> EnforcementError เด้งจาก is_blocked
        with patch.object(self.eng, "_run") as m:
            m.side_effect = [(0, ""), (1, "")]
            with self.assertRaises(EnforcementError):
                self.eng.add_block(IP)


class TestReadOnly(unittest.TestCase):
    def test_is_blocked_true(self):
        eng = PFSenseEnforcer(HOST)
        with patch.object(eng, "_run", return_value=(0, _show([IP]))):
            self.assertTrue(eng.is_blocked(IP))

    def test_is_blocked_false(self):
        eng = PFSenseEnforcer(HOST)
        with patch.object(eng, "_run", return_value=(0, _show(["10.0.0.9"]))):
            self.assertFalse(eng.is_blocked(IP))

    def test_get_blocked_ips_parses(self):
        eng = PFSenseEnforcer(HOST)
        with patch.object(eng, "_run",
                          return_value=(0, _show([IP, "10.0.0.9"]))):
            self.assertEqual(eng.get_blocked_ips(), {IP, "10.0.0.9"})


if __name__ == "__main__":
    unittest.main(verbosity=2)