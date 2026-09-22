"""
tests/test_risk.py — Risk Model v1 (Blueprint §3.5 — ล็อกแล้ว)

normalize table ที่ต้องตรงเป๊ะ:
    S  sev 1→75, 2→50, 3→25, custom critical (0)→100
    F  1→20, 2–3→40, 4–5→70, >5→100
    T  ≤10s→100, ≤30s→75, ≤60s→50, >60s→25     (absolute — ไม่ผูกกับ correlation window)
    C  allowlisted→0, known asset→30, unknown/external→80

golden case ของ Blueprint: S=75 F=70 T=100 C=80 ด้วย Set A -> 79.5 -> HIGH
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.models import CorrelationPattern, SourceContext
from security_engine.scoring.risk import (
    calculate, risk_level,
    factor_severity, factor_frequency, factor_temporal, factor_context,
    WEIGHT_SETS, SEVERITY_SCORE,
)

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)

UNKNOWN = SourceContext(allowlisted=False, known_asset=False)
KNOWN = SourceContext(allowlisted=False, known_asset=True)
ALLOWED = SourceContext(allowlisted=True, known_asset=False)

SRC = "198.51.100.77"


def make_pattern(count=5, severity=1, window=5.0, src=SRC):
    events = tuple({"src_ip": src, "dest_ip": "192.0.2.10", "severity": severity}
                   for _ in range(count))
    return CorrelationPattern(
        src_ip=src,
        window_start=T0,
        window_end=T0 + timedelta(seconds=window),
        event_count=count,
        max_severity=severity,
        events=events,
    )


# ---------- S: Severity ----------
class TestSeverityFactor:
    @pytest.mark.parametrize("severity,expected", [
        (1, 75.0),      # HIGH
        (2, 50.0),      # MEDIUM
        (3, 25.0),      # LOW
        (0, 100.0),     # custom critical signature (reserved ของโปรเจกต์)
    ])
    def test_severity_map(self, severity, expected):
        assert factor_severity(severity) == expected

    def test_severity_map_matches_blueprint_table(self):
        assert SEVERITY_SCORE == {0: 100.0, 1: 75.0, 2: 50.0, 3: 25.0}

    def test_missing_severity_is_zero(self):
        assert factor_severity(None) == 0.0

    def test_unknown_severity_scores_low_not_high(self):
        # severity นอกตาราง ต้องไม่กลายเป็นคะแนนสูงโดยบังเอิญ
        assert factor_severity(9) == 25.0

    def test_pattern_uses_most_severe(self):
        # Suricata: เลขน้อย = รุนแรงกว่า -> max_severity ของ [3,2,1] คือ 1
        events = ({"severity": 3}, {"severity": 2}, {"severity": 1})
        p = CorrelationPattern.from_dict(
            {"src_ip": SRC, "event_count": 3, "window_seconds": 2.0, "events": events})
        assert p.max_severity == 1
        assert factor_severity(p.max_severity) == 75.0


# ---------- F: Frequency tiers ----------
class TestFrequencyFactor:
    @pytest.mark.parametrize("count,expected", [
        (1, 20.0),
        (2, 40.0), (3, 40.0),
        (4, 70.0), (5, 70.0),
        (6, 100.0), (30, 100.0),
    ])
    def test_frequency_tiers(self, count, expected):
        assert factor_frequency(count) == expected

    def test_zero_events(self):
        assert factor_frequency(0) == 0.0


# ---------- T: Temporal lookup (absolute) ----------
class TestTemporalFactor:
    @pytest.mark.parametrize("window,expected", [
        (0.0, 100.0), (5.0, 100.0), (10.0, 100.0),      # ≤10s
        (10.1, 75.0), (30.0, 75.0),                     # ≤30s
        (30.1, 50.0), (60.0, 50.0),                     # ≤60s
        (60.1, 25.0), (600.0, 25.0),                    # >60s
    ])
    def test_temporal_lookup(self, window, expected):
        assert factor_temporal(window) == expected

    def test_temporal_is_absolute_not_window_ratio(self):
        # pattern กินเวลา 25s: ตารางให้ 75 เสมอ ไม่ว่า correlation window จะตั้งไว้เท่าไร
        # (สูตรเดิมคือ (1 − 25/30)×100 ≈ 16.7 ซึ่งไม่ใช่ของ Blueprint)
        assert factor_temporal(25.0) == 75.0


# ---------- C: Source context ----------
class TestContextFactor:
    def test_unknown_source_is_80(self):
        assert factor_context(UNKNOWN) == 80.0

    def test_known_lab_asset_is_30(self):
        assert factor_context(KNOWN) == 30.0

    def test_allowlisted_is_zero(self):
        assert factor_context(ALLOWED) == 0.0

    def test_allowlist_wins_over_known_asset(self):
        both = SourceContext(allowlisted=True, known_asset=True)
        assert factor_context(both) == 0.0

    def test_no_context_defaults_to_unknown(self):
        # ไม่มีข้อมูล = ไม่ลดความเสี่ยงให้ใคร
        assert factor_context(None) == 80.0


# ---------- Weight sets ----------
class TestWeightSets:
    @pytest.mark.parametrize("name,weights", [
        ("A", {"severity": 0.40, "frequency": 0.25, "temporal": 0.20, "context": 0.15}),
        ("B", {"severity": 0.30, "frequency": 0.30, "temporal": 0.25, "context": 0.15}),
        ("C", {"severity": 0.50, "frequency": 0.20, "temporal": 0.15, "context": 0.15}),
    ])
    def test_weight_sets_match_blueprint(self, name, weights):
        assert WEIGHT_SETS[name] == weights

    @pytest.mark.parametrize("name", ["A", "B", "C"])
    def test_weights_sum_to_one(self, name):
        assert sum(WEIGHT_SETS[name].values()) == pytest.approx(1.0)

    def test_invalid_weight_set_raises(self):
        with pytest.raises(ValueError):
            calculate(make_pattern(), UNKNOWN, weight_set="D")


# ---------- GOLDEN CASE: Blueprint §5 Step 5.1 ----------
class TestGoldenCase:
    def test_blueprint_golden_79_5(self):
        """5 HIGH events ภายใน 10s จาก source ที่ไม่รู้จัก ด้วย Set A
        75(0.40) + 70(0.25) + 100(0.20) + 80(0.15) = 30 + 17.5 + 20 + 12 = 79.5"""
        result = calculate(make_pattern(count=5, severity=1, window=5.0),
                           UNKNOWN, weight_set="A")
        assert result.severity_score == 75.0
        assert result.frequency_score == 70.0
        assert result.temporal_score == 100.0
        assert result.context_score == 80.0
        assert result.risk_score == 79.5
        assert result.risk_level == "HIGH"
        assert result.weight_set == "A"
        assert result.src_ip == SRC

    def test_allowlisted_pattern_keeps_risk_score(self):
        """Risk ≠ Decision: allowlisted source ได้ C=0 แต่ score ไม่เป็น 0
        30 + 17.5 + 20 + 0 = 67.5 -> HIGH (การยกเว้น block เป็นงานของ RULE-003)"""
        result = calculate(make_pattern(count=5, severity=1, window=5.0),
                           ALLOWED, weight_set="A")
        assert result.context_score == 0.0
        assert result.risk_score == 67.5
        assert result.risk_level == "HIGH"
        assert result.risk_score > 0

    def test_known_asset_lowers_score(self):
        # 30 + 17.5 + 20 + 4.5 = 72.0
        result = calculate(make_pattern(count=5, severity=1, window=5.0),
                           KNOWN, weight_set="A")
        assert result.context_score == 30.0
        assert result.risk_score == 72.0


# ---------- RiskResult contract (ตรงกับตาราง risk_assessments §3.4) ----------
class TestRiskResultContract:
    def test_has_db_field_names(self):
        r = calculate(make_pattern(), UNKNOWN)
        for name in ("severity_score", "frequency_score", "temporal_score",
                     "context_score", "weight_set", "risk_score", "risk_level"):
            assert hasattr(r, name), name

    def test_risk_model_does_not_decide(self):
        # Risk Engine ห้ามตัดสิน BLOCK/ALERT — ไม่มี field พวกนี้
        r = calculate(make_pattern(), UNKNOWN)
        for name in ("action", "decision", "rule_id", "block_duration"):
            assert not hasattr(r, name), name

    def test_factors_shorthand(self):
        r = calculate(make_pattern(), UNKNOWN)
        assert r.factors == {"S": 75.0, "F": 70.0, "T": 100.0, "C": 80.0}

    def test_default_weight_set_is_a(self):
        assert calculate(make_pattern(), UNKNOWN).weight_set == "A"


# ---------- legacy dict bridge (ชั่วคราวจนถึง STEP 5) ----------
class TestLegacyDictPattern:
    def test_accepts_dict_pattern(self):
        r = calculate({"src_ip": SRC, "event_count": 5, "window_seconds": 5.0,
                       "events": ({"severity": 1},)}, UNKNOWN)
        assert r.risk_score == 79.5

    def test_dict_window_seconds_preserved(self):
        p = CorrelationPattern.from_dict(
            {"src_ip": SRC, "event_count": 5, "window_seconds": 42.0, "events": ()})
        assert p.window_seconds == 42.0
        assert factor_temporal(p.window_seconds) == 50.0


# ---------- Risk level thresholds ----------
class TestRiskLevel:
    @pytest.mark.parametrize("score,level", [
        (100, "CRITICAL"), (85, "CRITICAL"), (80, "CRITICAL"),
        (79.5, "HIGH"), (60, "HIGH"),
        (59.9, "MEDIUM"), (30, "MEDIUM"),
        (29.9, "LOW"), (0, "LOW"),
    ])
    def test_thresholds(self, score, level):
        assert risk_level(score) == level


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
