"""
tests/test_sensitivity.py — Sensitivity Analysis (Blueprint Phase 5 Step 5.1 / T11)

pattern ชุดเดียวกัน + context เดียวกัน รันผ่าน Weight Set A/B/C แล้วตรวจว่า:
    - factor scores (S/F/T/C) ต้องเหมือนกันทุก set — weight ไม่แตะ normalize
    - risk_score เปลี่ยนตาม weight
    - risk_level คำนวณใหม่จาก score ของ set นั้น
    - weight_set ถูกบันทึกใน RiskResult (ต้องรู้ว่าตัวเลขมาจาก set ไหน)
    - Risk Model ไม่มี decision/action

*** ผลที่ได้เป็น Sensitivity Finding ไม่ใช่เหตุผลให้แก้ผลการทดลองทิ้ง ***
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.models import CorrelationPattern, SourceContext
from security_engine.scoring.risk import calculate, WEIGHT_SETS

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
SRC = "198.51.100.77"
UNKNOWN = SourceContext(allowlisted=False, known_asset=False)

# pattern เดียวกับ golden case: S=75, F=70, T=100, C=80
PATTERN = CorrelationPattern(
    src_ip=SRC,
    window_start=T0,
    window_end=T0 + timedelta(seconds=5),
    event_count=5,
    max_severity=1,
    events=tuple({"severity": 1, "dest_ip": "192.0.2.10"} for _ in range(5)),
)

# คำนวณมือจากตาราง §3.5:
#   A: 75(.40)+70(.25)+100(.20)+80(.15) = 30  +17.5+20  +12 = 79.5  HIGH
#   B: 75(.30)+70(.30)+100(.25)+80(.15) = 22.5+21  +25  +12 = 80.5  CRITICAL
#   C: 75(.50)+70(.20)+100(.15)+80(.15) = 37.5+14  +15  +12 = 78.5  HIGH
EXPECTED = {
    "A": (79.5, "HIGH"),
    "B": (80.5, "CRITICAL"),
    "C": (78.5, "HIGH"),
}


@pytest.fixture
def results():
    return {name: calculate(PATTERN, UNKNOWN, weight_set=name)
            for name in WEIGHT_SETS}


# ---- 1. factor scores ต้องไม่ขึ้นกับ weight set ----
def test_factor_scores_identical_across_weight_sets(results):
    factors = {name: (r.severity_score, r.frequency_score,
                      r.temporal_score, r.context_score)
               for name, r in results.items()}
    assert factors["A"] == factors["B"] == factors["C"] == (75.0, 70.0, 100.0, 80.0)


# ---- 2. risk_score / risk_level ตามแต่ละ set ----
@pytest.mark.parametrize("name", ["A", "B", "C"])
def test_expected_score_and_level(results, name):
    expected_score, expected_level = EXPECTED[name]
    assert results[name].risk_score == expected_score
    assert results[name].risk_level == expected_level


# ---- 3. weight_set ถูกบันทึกไว้ใน result ----
@pytest.mark.parametrize("name", ["A", "B", "C"])
def test_weight_set_recorded(results, name):
    assert results[name].weight_set == name


# ---- 4. score ต่างกันจริงระหว่าง set (ไม่ใช่คำนวณทิ้ง) ----
def test_scores_differ_between_sets(results):
    scores = {r.risk_score for r in results.values()}
    assert len(scores) == 3


# ---- 5. Sensitivity Finding: pattern เดียวกันข้ามเส้น CRITICAL ที่ Set B ----
def test_level_changes_with_weight_set(results):
    """บันทึกเป็น finding: pattern เดียวกันได้ HIGH ที่ Set A/C แต่ CRITICAL ที่ Set B
    (80.5 ≥ 80) — classification ไวต่อ weight แต่ RULE-001 ครอบทั้ง HIGH และ CRITICAL
    ดังนั้น decision ไม่เปลี่ยน ซึ่งเป็นสิ่งที่ต้องรายงาน ไม่ใช่แก้ตัวเลขทิ้ง"""
    assert results["A"].risk_level == "HIGH"
    assert results["B"].risk_level == "CRITICAL"
    assert results["C"].risk_level == "HIGH"


# ---- 6. Risk Model ไม่มี decision ----
@pytest.mark.parametrize("name", ["A", "B", "C"])
def test_no_decision_in_risk_result(results, name):
    for attr in ("action", "decision", "rule_id"):
        assert not hasattr(results[name], attr)


# ---- 7. ตารางเปรียบเทียบสำหรับ Report ----
def test_comparison_table_is_reproducible(results):
    table = [(name, r.severity_score, r.frequency_score, r.temporal_score,
              r.context_score, r.risk_score, r.risk_level)
             for name, r in sorted(results.items())]
    assert table == [
        ("A", 75.0, 70.0, 100.0, 80.0, 79.5, "HIGH"),
        ("B", 75.0, 70.0, 100.0, 80.0, 80.5, "CRITICAL"),
        ("C", 75.0, 70.0, 100.0, 80.0, 78.5, "HIGH"),
    ]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
