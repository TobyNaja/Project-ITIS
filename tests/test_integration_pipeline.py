"""
tests/test_integration_pipeline.py — Integration Test (Risk + Rule)

พิสูจน์ flow จริงต่อกันทั้งสาย (ยังไม่แตะ pfSense):

    CorrelationPattern + SourceContext -> calculate() -> RiskResult
    CorrelationPattern + allowlist     -> decide()    -> Decision

*** สองชั้นนี้ใช้ input คนละชุดโดยตั้งใจ ***
    Risk  : severity/frequency/temporal/context -> score + level (assessment)
    Rule  : raw severity + event count + window + allowlist -> action (decision)
    risk_level ไม่ใช่เงื่อนไขของ rule (§3.5)
"""
from datetime import datetime, timedelta, timezone

from security_engine.models import CorrelationPattern, SourceContext
from security_engine.scoring.risk import calculate
from security_engine.policy.rule_engine import (
    RuleEngine, MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK,
)
from security_engine.policy.rules_config import load_rules

SRC = "192.168.2.10"
T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)

UNKNOWN = SourceContext(allowlisted=False, known_asset=False)
ALLOWED = SourceContext(allowlisted=True, known_asset=False)

RULES = load_rules()


def make_pattern(spec, window, count=None, src=SRC):
    """spec = list ของ (severity, dest_ip)"""
    events = tuple({"src_ip": src, "dest_ip": dest, "severity": sev}
                   for sev, dest in spec)
    severities = [e["severity"] for e in events]
    return CorrelationPattern(
        src_ip=src,
        window_start=T0,
        window_end=T0 + timedelta(seconds=window),
        event_count=count if count is not None else len(events),
        max_severity=min(severities) if severities else None,
        events=events,
    )


def test_high_severity_pattern_flows_to_block():
    """T4: 5 HIGH (sev1) ≤10s not allowlisted
    Risk: S=75 F=70 T=100 C=80 -> 79.5 HIGH | Rule: RULE-001 -> BLOCK 300s"""
    pattern = make_pattern([(1, "a")] * 5, window=4.2)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine(RULES).decide(risk, pattern)
    assert risk.risk_score == 79.5
    assert risk.risk_level == "HIGH"
    assert decision.action == BLOCK
    assert decision.rule_id == "RULE-001"
    assert decision.block_duration == 300


def test_medium_severity_pattern_flows_to_alert():
    """T3: 5 MEDIUM (sev2) ≤10s -> RULE-002 -> ALERT
    Risk: S=50 F=70 T=100 C=80 -> 69.5 HIGH — แต่ rule ตัดสินจาก raw severity"""
    pattern = make_pattern(
        [(2, "a"), (2, "b"), (2, "c"), (2, "d"), (2, "e")], window=5.0)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine(RULES).decide(risk, pattern)
    assert risk.risk_score == 69.5
    assert decision.action == ALERT
    assert decision.rule_id == "RULE-002"
    assert decision.block_duration == 0


def test_low_severity_pattern_monitors_even_when_risk_is_medium():
    """5 LOW (sev3): risk_level = MEDIUM แต่ไม่มี rule ไหน match
    -> พิสูจน์ว่า decision ไม่ได้มาจาก risk_level"""
    pattern = make_pattern([(3, d) for d in ("a", "b", "c", "d", "e")], window=5.0)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine(RULES).decide(risk, pattern)
    assert risk.risk_score == 59.5
    assert risk.risk_level == "MEDIUM"
    assert decision.action == MONITOR
    assert decision.rule_id == "DEFAULT"


def test_insufficient_events_flows_to_monitor():
    """4 events < min_same_src_events 5 -> ตกทุก rule -> MONITOR
    (risk ยังสูง 79.5 — แต่ rule gate ไม่ผ่าน)"""
    pattern = make_pattern([(1, "x")] * 4, window=4.2, count=4)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine(RULES).decide(risk, pattern)
    assert risk.risk_level == "HIGH"
    assert decision.action == MONITOR


def test_allowlisted_critical_pattern_does_not_auto_block():
    """T5: Risk ≠ Decision — allowlisted -> C=0 -> 67.5 (ไม่ใช่ 0)
    แล้ว RULE-003 (priority 1) ชนะ RULE-001 -> NO_AUTO_BLOCK"""
    pattern = make_pattern([(1, "x")] * 5, window=1.0)
    risk = calculate(pattern, ALLOWED)
    decision = RuleEngine(RULES, allowlist={SRC}).decide(risk, pattern)
    assert risk.context_score == 0.0
    assert risk.risk_score == 67.5
    assert risk.risk_level == "HIGH"
    assert decision.action == NO_AUTO_BLOCK
    assert decision.rule_id == "RULE-003"
    assert decision.risk_score == 67.5      # เก็บไว้ audit ตาม FR-14
