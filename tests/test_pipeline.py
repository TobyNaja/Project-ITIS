"""
tests/test_pipeline.py — Phase 11.2 SecurityPipeline (unit)

fake correlator + fake lifecycle + real RuleEngine.
พิสูจน์ทั้ง 4 outcome + trace semantics (no-match→decision=None, t4/t5 meaning)
ไม่ยิง pfSense, ไม่มี thread จริง
"""
import pytest

from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import (
    RuleEngine, BLOCK, ALERT, MONITOR, NO_AUTO_BLOCK,
)

SRC = "192.168.2.10"


def event(src=SRC):
    return {"src_ip": src, "timestamp": "2026-09-20T10:00:00+00:00",
            "received_at": "2026-09-20T10:00:00.5+00:00"}


def make_match(severity, dests, count, window, src=SRC):
    evs = [{"src_ip": src, "dest_ip": d, "severity": severity} for d in dests]
    return {"src_ip": src, "event_count": count, "window_seconds": window, "events": evs}


class FakeCorrelator:
    """คืน match ที่กำหนดไว้ (None = ยังไม่ครบเกณฑ์)"""
    def __init__(self, match=None):
        self.match = match
        self.calls = 0

    def process(self, event):
        self.calls += 1
        return self.match


class FakeResult:
    def __init__(self, success):
        self.success = success


class FakeLifecycle:
    def __init__(self, block_ok=True):
        self.block_ok = block_ok
        self.blocked = []

    def block(self, decision):
        self.blocked.append(decision.src_ip)
        return FakeResult(self.block_ok)


def make_pipeline(match, allowlist=None, block_ok=True):
    corr = FakeCorrelator(match)
    rule = RuleEngine(allowlist=allowlist or set(), min_events=5, max_window=10.0)
    life = FakeLifecycle(block_ok=block_ok)
    return SecurityPipeline(corr, rule, life, min_events=5, window_max=10.0), life


# ---- no match ----
def test_no_match_decision_none(self=None):
    pipe, life = make_pipeline(match=None)
    tr = pipe.process(event())
    assert tr["correlation_matched"] is False
    assert tr["decision"] is None          # ยังไม่เข้า Rule Engine
    assert tr["t1_correlated"] is None
    assert life.blocked == []              # ไม่ enforce


# ---- BLOCK ----
def test_block_flows_to_lifecycle():
    # HIGH: sev2 + 3A/2B + 4.2s -> R65.6 -> HIGH -> BLOCK
    match = make_match(2, ["a", "a", "a", "b", "b"], count=5, window=4.2)
    pipe, life = make_pipeline(match)
    tr = pipe.process(event())
    assert tr["decision"] == BLOCK
    assert life.blocked == [SRC]
    # trace ครบทุก stage
    assert tr["t1_correlated"] is not None
    assert tr["t2_risk"] is not None
    assert tr["t3_decision"] is not None
    assert tr["t4_enforce_req"] is not None
    assert tr["t5_enforce_ok"] is not None      # block_ok=True


def test_block_verify_fail_no_t5():
    # block() คืน success=False -> t4 มี แต่ t5 ไม่มี
    match = make_match(2, ["a", "a", "a", "b", "b"], count=5, window=4.2)
    pipe, life = make_pipeline(match, block_ok=False)
    tr = pipe.process(event())
    assert tr["decision"] == BLOCK
    assert tr["t4_enforce_req"] is not None
    assert tr["t5_enforce_ok"] is None          # verify ไม่ผ่าน


# ---- ALERT ----
def test_alert_does_not_enforce():
    # MEDIUM: sev3 + 5 dest + 5.0s -> R48 -> MEDIUM -> ALERT
    match = make_match(3, ["a", "b", "c", "d", "e"], count=5, window=5.0)
    pipe, life = make_pipeline(match)
    tr = pipe.process(event())
    assert tr["decision"] == ALERT
    assert life.blocked == []                   # ไม่ enforce
    assert tr["t4_enforce_req"] is None


# ---- MONITOR (correlation คืน match แต่ตก gate ของ Rule Engine) ----
def test_monitor_gate_fail():
    # correlator คืน match ที่ event_count=4 (<min 5) -> RuleEngine ตกทุก rule -> MONITOR
    # (นี่คือ MONITOR path จริงในระบบ: เข้า Rule Engine แล้ว แต่ไม่เข้าเกณฑ์ block/alert)
    match = make_match(1, ["a", "a", "a", "a"], count=4, window=4.2)
    pipe, life = make_pipeline(match)
    tr = pipe.process(event())
    assert tr["decision"] == MONITOR
    assert tr["correlation_matched"] is True     # เข้า Rule Engine แล้ว (ต่างจาก no-match)
    assert life.blocked == []


# ---- NO_AUTO_BLOCK (allowlist) ----
def test_allowlisted_no_auto_block():
    match = make_match(1, ["x"] * 5, count=5, window=1.0)   # CRITICAL
    pipe, life = make_pipeline(match, allowlist={SRC})
    tr = pipe.process(event())
    assert tr["decision"] == NO_AUTO_BLOCK
    assert life.blocked == []                   # allowlist ชนะ ไม่ enforce
    assert tr["t4_enforce_req"] is None


# ---- trace: แยก event_time / received_at ----
def test_trace_separates_clocks():
    pipe, _ = make_pipeline(match=None)
    tr = pipe.process(event())
    assert tr["event_time"] == "2026-09-20T10:00:00+00:00"
    assert tr["received_at"] == "2026-09-20T10:00:00.5+00:00"
    assert isinstance(tr["t0_received"], float)   # monotonic


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))