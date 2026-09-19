"""
tests/test_rule_engine.py — Unit test สำหรับ Phase 6 Rule Engine
รัน: python3 -m pytest tests/test_rule_engine.py -v

ยึดกฎที่ล็อก:
  RULE-003 allowlist              -> NO_AUTO_BLOCK  (มาก่อนเสมอ)
  RULE-001 HIGH+ / gate           -> BLOCK
  RULE-002 MEDIUM / gate          -> ALERT
  default                         -> MONITOR
  gate = event_count ≥ min_events AND window_seconds ≤ max_window
"""
import unittest

from security_engine.policy.rule_engine import (
    RuleEngine, Decision,
    MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK, BLOCK_DURATION,
)


class FakeRisk:
    """แทน RiskResult — Rule Engine ใช้แค่ src_ip กับ risk_level"""
    def __init__(self, src_ip, risk_level):
        self.src_ip = src_ip
        self.risk_level = risk_level


def corr(count=5, window=4.2, src="192.168.2.10"):
    return {"src_ip": src, "event_count": count, "window_seconds": window}


class TestBlock(unittest.TestCase):
    def test_high_full_gate_blocks(self):
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "HIGH"), corr(5, 4.2))
        self.assertEqual(d.action, BLOCK)
        self.assertEqual(d.rule_id, "RULE-001")
        self.assertEqual(d.block_duration, BLOCK_DURATION)

    def test_critical_also_blocks(self):
        # จุดสำคัญ: CRITICAL ต้อง block ด้วย (ไม่หลุดเพราะ != HIGH)
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "CRITICAL"), corr(5, 4.2))
        self.assertEqual(d.action, BLOCK)
        self.assertEqual(d.rule_id, "RULE-001")

    def test_high_but_window_too_wide_no_block(self):
        # window 12s > 10s -> ตก gate -> MONITOR
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "HIGH"), corr(5, 12.0))
        self.assertEqual(d.action, MONITOR)

    def test_high_but_too_few_events_no_block(self):
        # 4 events < min 5 -> ตก gate -> MONITOR
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "HIGH"), corr(4, 4.2))
        self.assertEqual(d.action, MONITOR)

    def test_window_exactly_10_still_blocks(self):
        # boundary: ≤10s รวม 10.0 พอดี
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "HIGH"), corr(5, 10.0))
        self.assertEqual(d.action, BLOCK)


class TestAllowlist(unittest.TestCase):
    def test_allowlist_wins_over_block(self):
        # แม้เข้าเกณฑ์ BLOCK ทุกอย่าง allowlist ต้องชนะ -> NO_AUTO_BLOCK
        eng = RuleEngine(allowlist={"192.168.2.10"}, min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("192.168.2.10", "CRITICAL"), corr(9, 1.0))
        self.assertEqual(d.action, NO_AUTO_BLOCK)
        self.assertEqual(d.rule_id, "RULE-003")

    def test_non_allowlisted_still_blocks(self):
        eng = RuleEngine(allowlist={"10.0.0.1"}, min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("192.168.2.10", "HIGH"), corr(5, 4.2))
        self.assertEqual(d.action, BLOCK)

    def test_empty_allowlist_default(self):
        eng = RuleEngine()   # ไม่ส่ง allowlist -> set ว่าง
        d = eng.decide(FakeRisk("1.2.3.4", "HIGH"), corr(5, 4.2))
        self.assertEqual(d.action, BLOCK)


class TestAlert(unittest.TestCase):
    def test_medium_full_gate_alerts(self):
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "MEDIUM"), corr(5, 4.2))
        self.assertEqual(d.action, ALERT)
        self.assertEqual(d.rule_id, "RULE-002")

    def test_medium_no_gate_monitors(self):
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "MEDIUM"), corr(3, 4.2))
        self.assertEqual(d.action, MONITOR)


class TestMonitor(unittest.TestCase):
    def test_low_is_monitor(self):
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "LOW"), corr(5, 4.2))
        self.assertEqual(d.action, MONITOR)
        self.assertEqual(d.rule_id, "DEFAULT")


class TestNoEnforcement(unittest.TestCase):
    def test_decision_carries_no_side_effect(self):
        # Rule Engine ต้องคืน Decision เท่านั้น ไม่มี attribute ที่สั่ง enforce
        eng = RuleEngine(min_events=5, max_window=10.0)
        d = eng.decide(FakeRisk("1.2.3.4", "HIGH"), corr(5, 4.2))
        self.assertIsInstance(d, Decision)
        # BLOCK บอกแค่ block_duration ให้ Phase 8 ไปใช้ ไม่ได้ block เอง
        self.assertEqual(d.block_duration, BLOCK_DURATION)


if __name__ == "__main__":
    unittest.main(verbosity=2)