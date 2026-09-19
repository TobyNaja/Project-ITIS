"""
tests/test_integration_pipeline.py — Phase 7 Integration Test

พิสูจน์ flow จริงต่อกันทั้งสาย (ยังไม่แตะ pfSense):

    Correlation Pattern -> assess() -> RiskResult -> decide() -> Decision

แต่ละ scenario ออกแบบให้ risk_level ตรงกับชื่อ test จริง
(คำนวณจากสูตรที่ล็อกไว้ ไม่ได้เดา) เพื่อพิสูจน์ทั้ง Risk -> Decision
ไม่ใช่แค่ปลายทาง
"""
from security_engine.scoring.risk import assess
from security_engine.policy.rule_engine import (
    RuleEngine, MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK,
)

SRC = "192.168.2.10"

def _events(spec, src=SRC):
    """spec = list ของ (severity, dest_ip)"""
    return [{"src_ip": src, "dest_ip": dest, "severity": sev}
            for sev, dest in spec]

def make_correlation(spec, window, count=None, src=SRC):
    events = _events(spec, src)
    return {
        "src_ip": src,
        "event_count": count if count is not None else len(events),
        "window_seconds": window,
        "events": events,
    }

def test_high_pattern_flows_to_block():
    # S=50 (sev2), F=100 (5 ev), T=58 (4.2s), C=60 (3A/2B) -> R=65.6 -> HIGH
    correlation = make_correlation(
        [(2, "a"), (2, "a"), (2, "a"), (2, "b"), (2, "b")], window=4.2)
    risk = assess(correlation)
    decision = RuleEngine().decide(risk, correlation)
    assert risk.risk_level == "HIGH"
    assert decision.action == BLOCK
    assert decision.rule_id == "RULE-001"

def test_medium_pattern_flows_to_alert():
    # S=25 (sev3), F=100 (5 ev), T=50 (5.0s), C=20 (5 dest) -> R=48.0 -> MEDIUM
    correlation = make_correlation(
        [(3, "a"), (3, "b"), (3, "c"), (3, "d"), (3, "e")], window=5.0)
    risk = assess(correlation)
    decision = RuleEngine().decide(risk, correlation)
    assert risk.risk_level == "MEDIUM"
    assert decision.action == ALERT
    assert decision.rule_id == "RULE-002"

def test_insufficient_events_flows_to_monitor():
    # 4 events < min 5 -> correlation gate ตก -> MONITOR (ไม่ว่า risk เท่าไร)
    correlation = make_correlation([(1, "x")] * 4, window=4.2, count=4)
    risk = assess(correlation)
    decision = RuleEngine().decide(risk, correlation)
    assert decision.action == MONITOR

def test_allowlisted_critical_pattern_does_not_auto_block():
    # sev1 เป้าเดียว window 1.0 -> R=88 -> CRITICAL แต่ allowlist ต้องชนะ
    correlation = make_correlation([(1, "x")] * 5, window=1.0)
    risk = assess(correlation)
    decision = RuleEngine(allowlist={SRC}).decide(risk, correlation)
    assert risk.risk_level == "CRITICAL"
    assert decision.action == NO_AUTO_BLOCK
    assert decision.rule_id == "RULE-003"