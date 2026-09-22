"""
tests/test_rule_engine.py — Rule Engine (Blueprint §3.6, YAML-driven)

กฎทั้งหมดมาจาก config/rules.yaml:
  RULE-003 priority 1  source_in_allowlist: true                  -> NO_AUTO_BLOCK
  RULE-001 priority 2  HIGH + ≥5 events + ≤10s + not allowlisted  -> BLOCK (300s)
  RULE-002 priority 3  MEDIUM + ≥5 events + ≤10s                  -> ALERT
  default                                                          -> MONITOR

*** condition ใช้ raw Suricata severity ไม่ใช่ risk_level *** (§3.5)
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.models import CorrelationPattern
from security_engine.policy.rule_engine import (
    RuleEngine, Decision, MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK,
)
from security_engine.policy.rules_config import load_rules, RuleSet

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
SRC = "192.168.2.10"
BLOCK_DURATION = 300        # ตาม config/rules.yaml (RULE-001)


@pytest.fixture(scope="module")
def rules():
    """RuleSet จริงจาก config/rules.yaml ของ repo"""
    return load_rules()


def pattern(severity=1, count=5, window=4.2, src=SRC):
    return CorrelationPattern(
        src_ip=src,
        window_start=T0,
        window_end=T0 + timedelta(seconds=window),
        event_count=count,
        max_severity=severity,
        events=tuple({"severity": severity} for _ in range(count)),
    )


class FakeRisk:
    """แทน RiskResult — Rule Engine ใช้แค่ src_ip (score/level เก็บไว้ audit)"""
    def __init__(self, src_ip=SRC, risk_level="HIGH", risk_score=79.5):
        self.src_ip = src_ip
        self.risk_level = risk_level
        self.risk_score = risk_score


# ---------- RULE-001: BLOCK ----------
class TestBlock:
    def test_high_severity_full_gate_blocks(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1, count=5, window=4.2))
        assert d.action == BLOCK
        assert d.rule_id == "RULE-001"
        assert d.block_duration == BLOCK_DURATION

    def test_critical_severity_also_blocks(self, rules):
        # severity 0 = custom critical -> รุนแรงกว่า HIGH -> ยัง match min_severity HIGH
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=0))
        assert d.action == BLOCK
        assert d.rule_id == "RULE-001"

    def test_window_too_wide_no_block(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1, window=12.0))
        assert d.action == MONITOR

    def test_too_few_events_no_block(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1, count=4))
        assert d.action == MONITOR

    def test_window_exactly_10_still_blocks(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1, window=10.0))
        assert d.action == BLOCK

    def test_block_duration_comes_from_rules_yaml(self, rules):
        rule = next(r for r in rules if r.id == "RULE-001")
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1))
        assert d.block_duration == rule.block_duration_sec


# ---------- RULE-002: ALERT ----------
class TestAlert:
    def test_medium_severity_full_gate_alerts(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(risk_level="MEDIUM"),
                                     pattern(severity=2, count=5, window=4.2))
        assert d.action == ALERT
        assert d.rule_id == "RULE-002"
        assert d.block_duration == 0

    def test_medium_no_gate_monitors(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(risk_level="MEDIUM"),
                                     pattern(severity=2, count=3))
        assert d.action == MONITOR


# ---------- หัวใจของ STEP 3: rule ใช้ raw severity ไม่ใช่ risk_level ----------
class TestSeveritySemantics:
    def test_low_severity_does_not_alert_even_if_risk_level_medium(self, rules):
        """5 LOW events (severity 3) ที่ risk model ให้ risk_level = MEDIUM
        ต้อง **ไม่** match RULE-002 เพราะ condition คือ raw severity ≥ MEDIUM"""
        d = RuleEngine(rules).decide(FakeRisk(risk_level="MEDIUM"),
                                     pattern(severity=3, count=5, window=4.2))
        assert d.action == MONITOR
        assert d.rule_id == "DEFAULT"

    def test_high_severity_blocks_even_if_risk_level_low(self, rules):
        """กลับกัน: risk_level LOW แต่ severity 1 + ครบ gate -> ยัง BLOCK
        (พิสูจน์ว่า rule ไม่ได้แอบอ่าน risk_level)"""
        d = RuleEngine(rules).decide(FakeRisk(risk_level="LOW", risk_score=12.0),
                                     pattern(severity=1, count=5, window=4.2))
        assert d.action == BLOCK
        assert d.rule_id == "RULE-001"

    def test_missing_severity_never_matches_severity_rules(self, rules):
        p = CorrelationPattern(src_ip=SRC, window_start=T0,
                               window_end=T0 + timedelta(seconds=1),
                               event_count=9, max_severity=None)
        d = RuleEngine(rules).decide(FakeRisk(), p)
        assert d.action == MONITOR


# ---------- Priority / safety override ----------
class TestPriority:
    def test_allowlist_wins_over_block(self, rules):
        """allowlisted + 5 HIGH ≤10s: RULE-003 (priority 1) ต้องมาก่อน RULE-001"""
        eng = RuleEngine(rules, allowlist={SRC})
        d = eng.decide(FakeRisk(risk_level="CRITICAL"), pattern(severity=1, count=9, window=1.0))
        assert d.action == NO_AUTO_BLOCK
        assert d.rule_id == "RULE-003"
        assert d.block_duration == 0

    def test_non_allowlisted_still_blocks(self, rules):
        eng = RuleEngine(rules, allowlist={"10.0.0.1"})
        d = eng.decide(FakeRisk(), pattern(severity=1))
        assert d.action == BLOCK

    def test_empty_allowlist(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1))
        assert d.action == BLOCK

    def test_rules_evaluated_in_priority_order(self, rules):
        assert [r.priority for r in rules] == sorted(r.priority for r in rules)
        assert [r.id for r in rules] == ["RULE-003", "RULE-001", "RULE-002"]

    def test_allowlisted_low_severity_still_no_auto_block(self, rules):
        """allowlist ไม่มีเงื่อนไข severity — match ทุกกรณีที่ source อยู่ในลิสต์"""
        eng = RuleEngine(rules, allowlist={SRC})
        d = eng.decide(FakeRisk(risk_level="LOW"), pattern(severity=3, count=1, window=0.5))
        assert d.action == NO_AUTO_BLOCK


# ---------- default ----------
class TestDefault:
    def test_no_rule_match_uses_default_action(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(risk_level="LOW"), pattern(severity=3, count=1))
        assert d.action == rules.default_action == MONITOR
        assert d.rule_id == "DEFAULT"


# ---------- contract ----------
class TestEngineContract:
    def test_requires_ruleset(self):
        with pytest.raises(TypeError):
            RuleEngine({"rules": []})

    def test_no_hidden_default_loading(self):
        # RuleEngine() เปล่า ๆ ต้องใช้ไม่ได้ — dependency ต้องชัด
        with pytest.raises(TypeError):
            RuleEngine()

    def test_decision_is_data_only(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1))
        assert isinstance(d, Decision)
        for attr in ("enforce", "block", "apply", "execute"):
            assert not hasattr(d, attr)

    def test_decision_carries_risk_for_audit(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(risk_level="HIGH", risk_score=79.5),
                                     pattern(severity=1))
        assert d.risk_level == "HIGH"
        assert d.risk_score == 79.5

    def test_reason_is_human_readable(self, rules):
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1))
        assert "RULE-001" in d.reason
        assert "events" in d.reason

    def test_accepts_legacy_dict_pattern(self, rules):
        d = RuleEngine(rules).decide(
            FakeRisk(), {"src_ip": SRC, "event_count": 5, "window_seconds": 4.2,
                         "max_severity": 1, "events": ()})
        assert d.action == BLOCK


# ---------- custom rule set (พิสูจน์ว่า config เป็นคนกำหนดพฤติกรรมจริง) ----------
class TestConfigDrivenBehaviour:
    def test_custom_rules_change_decision(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text(
            "rules:\n"
            "  - id: 'ONLY-ALERT'\n"
            "    priority: 1\n"
            "    condition:\n"
            "      min_severity: 'HIGH'\n"
            "      min_same_src_events: 5\n"
            "    action: 'ALERT'\n"
            "default_action: 'MONITOR'\n", encoding="utf-8")
        d = RuleEngine(load_rules(f)).decide(FakeRisk(), pattern(severity=1))
        assert d.action == ALERT
        assert d.rule_id == "ONLY-ALERT"

    def test_priority_order_decides_winner(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text(
            "rules:\n"
            "  - id: 'SECOND'\n"
            "    priority: 2\n"
            "    condition: {min_same_src_events: 1}\n"
            "    action: 'ALERT'\n"
            "  - id: 'FIRST'\n"
            "    priority: 1\n"
            "    condition: {min_same_src_events: 1}\n"
            "    action: 'NO_AUTO_BLOCK'\n"
            "default_action: 'MONITOR'\n", encoding="utf-8")
        rules = load_rules(f)
        assert isinstance(rules, RuleSet)
        d = RuleEngine(rules).decide(FakeRisk(), pattern(severity=1))
        assert d.rule_id == "FIRST"           # priority 1 ชนะแม้เขียนทีหลังในไฟล์


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
