"""
tests/test_risk.py — Unit test สำหรับ Phase 5 Risk Engine
รัน: python3 -m pytest tests/test_risk.py -v
หรือ: python3 -m unittest tests.test_risk -v

ยึด Phase 5 Specification ที่ล็อกไว้:
  Severity:  Suricata 1→75, 2→50, 3→25, 0/custom→100
  Level:     0–29 LOW | 30–59 MEDIUM | 60–79 HIGH | 80–100 CRITICAL
  C:         Target Concentration = max_dest_count / total × 100
"""
import unittest

from security_engine.scoring.risk import (
    assess, risk_level,
    factor_severity, factor_frequency, factor_temporal,
    factor_target_concentration,
    W_SEVERITY, W_FREQUENCY, W_TEMPORAL, W_TARGET_CONCENTRATION,
)


def make_events(n, severity=1, dest_ip="192.168.1.11"):
    """สร้าง normalized events n ตัว ยิงเป้าเดียวกันหมด"""
    return [
        {"src_ip": "192.168.2.10", "dest_ip": dest_ip,
         "severity": severity, "signature_id": 1000001}
        for _ in range(n)
    ]


class TestFactors(unittest.TestCase):
    def test_severity_high_is_75(self):
        # Suricata sev 1 = HIGH -> 75 (ไม่ใช่ 100)
        self.assertEqual(factor_severity(make_events(5, severity=1)), 75.0)

    def test_severity_medium_is_50(self):
        self.assertEqual(factor_severity(make_events(5, severity=2)), 50.0)

    def test_severity_low_is_25(self):
        self.assertEqual(factor_severity(make_events(5, severity=3)), 25.0)

    def test_severity_critical_is_100(self):
        # sev 0 = custom/critical -> 100
        self.assertEqual(factor_severity(make_events(5, severity=0)), 100.0)

    def test_severity_uses_worst(self):
        # มี sev 3 กับ sev 1 ปนกัน -> ต้องเอา 1 (รุนแรงสุด) = 75
        events = [{"severity": 3, "dest_ip": "x"},
                  {"severity": 1, "dest_ip": "x"}]
        self.assertEqual(factor_severity(events), 75.0)

    def test_severity_empty(self):
        self.assertEqual(factor_severity([]), 0.0)

    def test_frequency_exact_min_is_100(self):
        self.assertEqual(factor_frequency(5, min_events=5), 100.0)

    def test_frequency_clamped_over_min(self):
        self.assertEqual(factor_frequency(10, min_events=5), 100.0)

    def test_temporal_zero_window_is_100(self):
        self.assertAlmostEqual(factor_temporal(0.0, window_max=10.0), 100.0)

    def test_temporal_half_window_is_50(self):
        self.assertAlmostEqual(factor_temporal(5.0, window_max=10.0), 50.0)

    def test_temporal_full_window_zero(self):
        self.assertAlmostEqual(factor_temporal(10.0, window_max=10.0), 0.0)

    def test_temporal_over_window_clamped_zero(self):
        self.assertAlmostEqual(factor_temporal(15.0, window_max=10.0), 0.0)

    def test_temporal_scenario_value(self):
        # window 4.2s -> (10-4.2)/10*100 = 58
        self.assertAlmostEqual(factor_temporal(4.2, window_max=10.0), 58.0, places=1)

    def test_concentration_single_dest_is_100(self):
        self.assertEqual(factor_target_concentration(make_events(5)), 100.0)

    def test_concentration_3a_2b_is_60(self):
        # 3 events -> IP A, 2 events -> IP B -> max=3, total=5 -> 60
        events = ([{"dest_ip": "10.0.0.1"}] * 3) + ([{"dest_ip": "10.0.0.2"}] * 2)
        self.assertEqual(factor_target_concentration(events), 60.0)

    def test_concentration_all_different_is_20(self):
        # 5 events -> 5 เป้าต่างกัน -> max=1, total=5 -> 20
        events = [{"dest_ip": f"10.0.0.{i}"} for i in range(5)]
        self.assertEqual(factor_target_concentration(events), 20.0)

class TestAssess(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(
            W_SEVERITY + W_FREQUENCY + W_TEMPORAL + W_TARGET_CONCENTRATION, 1.0
        )
    def test_scenario_high(self):
        # เคสจริง: 5 events, HIGH (sev 1), window 4.2s, เป้าเดียว
        corr = {
            "src_ip": "192.168.2.10",
            "event_count": 5,
            "window_seconds": 4.2,
            "events": make_events(5, severity=1),
        }
        r = assess(corr, min_events=5, window_max=10.0)
        # S=75, F=100, T=58, C=100
        # R = 30 + 25 + 11.6 + 15 = 81.6
        self.assertEqual(r.factors["S"], 75.0)
        self.assertEqual(r.factors["F"], 100.0)
        self.assertAlmostEqual(r.factors["T"], 58.0, places=1)
        self.assertEqual(r.factors["C"], 100.0)
        self.assertAlmostEqual(r.risk_score, 81.6, places=1)
        self.assertEqual(r.risk_level, "CRITICAL")

    def test_manual_formula_matches(self):
        corr = {
            "src_ip": "1.1.1.1",
            "event_count": 5,
            "window_seconds": 5.0,      # T = 50
            "events": make_events(5, severity=2),   # S = 50
        }
        r = assess(corr, min_events=5, window_max=10.0)
        expected = 50 * 0.40 + 100 * 0.25 + 50 * 0.20 + 100 * 0.15
        self.assertAlmostEqual(r.risk_score, round(expected, 2), places=2)

    def test_low_severity_spread_is_medium(self):
        # sev 3, มาแค่พอดี min, กระจาย 5 เป้า, window เต็ม
        corr = {
            "src_ip": "2.2.2.2",
            "event_count": 5,
            "window_seconds": 9.9,
            "events": [{"severity": 3, "dest_ip": f"10.0.0.{i}"}
                       for i in range(5)],
        }
        r = assess(corr, min_events=5, window_max=10.0)
        # S=25, F=100, T~1, C=20 -> R = 10 + 25 + 0.2 + 3 = 38.2
        self.assertAlmostEqual(r.risk_score, 38.2, places=1)
        self.assertEqual(r.risk_level, "MEDIUM")   # 30–59 = MEDIUM


class TestRiskLevel(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(risk_level(85), "CRITICAL")
        self.assertEqual(risk_level(80), "CRITICAL")
        self.assertEqual(risk_level(79), "HIGH")
        self.assertEqual(risk_level(60), "HIGH")
        self.assertEqual(risk_level(59), "MEDIUM")
        self.assertEqual(risk_level(40), "MEDIUM")
        self.assertEqual(risk_level(30), "MEDIUM")
        self.assertEqual(risk_level(29), "LOW")
        self.assertEqual(risk_level(0), "LOW")

if __name__ == "__main__":
    unittest.main(verbosity=2)