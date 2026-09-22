"""
tests/test_integration_pipeline.py — Integration Test (Risk -> Decision)

พิสูจน์ flow จริงต่อกันทั้งสาย (ยังไม่แตะ pfSense):

    CorrelationPattern + SourceContext -> calculate() -> RiskResult -> decide() -> Decision

ค่าทุกตัวคำนวณจากตาราง §3.5 ที่ล็อกไว้ ไม่ได้เดา:
    S  sev1=75 sev2=50 sev3=25 | F  4–5 events=70, >5=100 | T ≤10s=100 | C unknown=80, allowlisted=0
"""
from datetime import datetime, timedelta, timezone

from security_engine.models import CorrelationPattern, SourceContext
from security_engine.scoring.risk import calculate
from security_engine.policy.rule_engine import (
    RuleEngine, MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK,
)

SRC = "192.168.2.10"
T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)

UNKNOWN = SourceContext(allowlisted=False, known_asset=False)
ALLOWED = SourceContext(allowlisted=True, known_asset=False)


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


def test_high_pattern_flows_to_block():
    # S=50 (sev2), F=70 (5 ev), T=100 (4.2s), C=80 -> 20+17.5+20+12 = 69.5 -> HIGH
    pattern = make_pattern(
        [(2, "a"), (2, "a"), (2, "a"), (2, "b"), (2, "b")], window=4.2)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine().decide(risk, pattern)
    assert risk.risk_score == 69.5
    assert risk.risk_level == "HIGH"
    assert decision.action == BLOCK
    assert decision.rule_id == "RULE-001"


def test_medium_pattern_flows_to_alert():
    # S=25 (sev3), F=70 (5 ev), T=100 (5.0s), C=80 -> 10+17.5+20+12 = 59.5 -> MEDIUM
    pattern = make_pattern(
        [(3, "a"), (3, "b"), (3, "c"), (3, "d"), (3, "e")], window=5.0)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine().decide(risk, pattern)
    assert risk.risk_score == 59.5
    assert risk.risk_level == "MEDIUM"
    assert decision.action == ALERT
    assert decision.rule_id == "RULE-002"


def test_insufficient_events_flows_to_monitor():
    # 4 events < min 5 -> correlation gate ตก -> MONITOR (ไม่ว่า risk เท่าไร)
    pattern = make_pattern([(1, "x")] * 4, window=4.2, count=4)
    risk = calculate(pattern, UNKNOWN)
    decision = RuleEngine().decide(risk, pattern)
    assert risk.risk_level == "HIGH"        # 79.5 — risk สูงแต่ gate ไม่ผ่าน
    assert decision.action == MONITOR


def test_allowlisted_critical_pattern_does_not_auto_block():
    """Risk ≠ Decision: allowlisted -> C=0 -> 30+17.5+20+0 = 67.5 (HIGH ไม่ใช่ 0)
    แล้ว RULE-003 เป็นคนยกเว้นการ block ต่างหาก"""
    pattern = make_pattern([(1, "x")] * 5, window=1.0)
    risk = calculate(pattern, ALLOWED)
    decision = RuleEngine(allowlist={SRC}).decide(risk, pattern)
    assert risk.context_score == 0.0
    assert risk.risk_score == 67.5
    assert risk.risk_level == "HIGH"
    assert decision.action == NO_AUTO_BLOCK
    assert decision.rule_id == "RULE-003"
