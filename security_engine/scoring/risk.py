"""
security_engine/scoring/risk.py — Phase 5 Risk Engine

รับ correlation pattern (output ของ CorrelationEngine.process) แล้วคืน:
  - Risk Score R (0-100)
  - Risk Level (LOW / MEDIUM / HIGH / CRITICAL)
  - Factor breakdown (S, F, T, C แต่ละตัว 0-100)

Model ที่ล็อกไว้ (Phase 5 Specification):
  R = (S × 0.40) + (F × 0.25) + (T × 0.20) + (C × 0.15)

  S = Severity            F = Frequency
  T = Temporal            C = Target Concentration

Risk Engine นี้ "ไม่สั่ง BLOCK" — คืน score/level ให้ Phase 6 Rule Engine ตัดสินเอง
"""
from collections import Counter
from dataclasses import dataclass, field

# ---- น้ำหนักตาม ground-truth (ห้ามแก้เกินจากที่ล็อก) ----
W_SEVERITY = 0.40
W_FREQUENCY = 0.25
W_TEMPORAL = 0.20
W_TARGET_CONCENTRATION = 0.15

# ---- พารามิเตอร์ normalize (ปรับได้ตาม Correlation config) ----
DEFAULT_MIN_EVENTS = 5      # ต้องตรงกับ CorrelationEngine.min_events
DEFAULT_WINDOW_MAX = 10.0   # ต้องตรงกับ CorrelationEngine window_seconds

# Severity mapping used by this project:
#   1 = HIGH    -> 75
#   2 = MEDIUM  -> 50
#   3 = LOW     -> 25
#   0 = reserved for project-defined CRITICAL events -> 100
#       (ไม่ใช่การตีความ Suricata severity 0 = critical โดยอัตโนมัติ;
#        0 เป็น reserved value ของโปรเจกต์ ต้องมาจาก custom critical
#        signature / mapping ของเราเองเท่านั้น)
_SEVERITY_SCORE = {0: 100.0, 1: 75.0, 2: 50.0, 3: 25.0}

# ---- เกณฑ์ Risk Level ตาม spec ----
#   0–29 LOW | 30–59 MEDIUM | 60–79 HIGH | 80–100 CRITICAL
LEVEL_THRESHOLDS = (
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (30.0, "MEDIUM"),
    (0.0, "LOW"),
)


@dataclass
class RiskResult:
    src_ip: str
    risk_score: float
    risk_level: str
    factors: dict = field(default_factory=dict)

    def __str__(self):
        f = self.factors
        return (
            f"[RISK] {self.src_ip} R={self.risk_score:.1f} {self.risk_level} "
            f"(S={f['S']:.0f} F={f['F']:.0f} T={f['T']:.0f} C={f['C']:.0f})"
        )


def _clamp(x, lo=0.0, hi=100.0):
    return max(lo, min(hi, x))


def factor_severity(events) -> float:
    """S: จาก severity ที่รุนแรงสุด (เลขน้อยสุด) ใน bucket
    Suricata 1→75, 2→50, 3→25, 0/custom→100"""
    sevs = [e.get("severity") for e in events if e.get("severity") is not None]
    if not sevs:
        return 0.0
    worst = min(sevs)                       # เลขน้อย = รุนแรงกว่า
    return _SEVERITY_SCORE.get(worst, 25.0)


def factor_frequency(event_count, min_events=DEFAULT_MIN_EVENTS) -> float:
    """F: จำนวน event เทียบ min_events, ตันที่ 100"""
    if min_events <= 0:
        return 100.0
    return _clamp(event_count / min_events * 100.0)


def factor_temporal(window_seconds, window_max=DEFAULT_WINDOW_MAX) -> float:
    """T: ยิ่งอัดแน่น (window แคบ) ยิ่งสูง
    window=0→100, window=5→50, window=10→0, window>10→0 (clamp)"""
    if window_max <= 0:
        return 0.0
    return _clamp((1.0 - window_seconds / window_max) * 100.0)


def factor_target_concentration(events) -> float:
    """C: จำนวน event ที่ยิงไป dest ยอดฮิตสุด ÷ total × 100
    5 event เป้าเดียว = 100; 3A+2B = 60; 5 เป้าต่างกัน = 20"""
    dests = [e.get("dest_ip") for e in events if e.get("dest_ip") is not None]
    total = len(dests)
    if total == 0:
        return 0.0
    top = Counter(dests).most_common(1)[0][1]   # จำนวนของ dest ที่พบมากสุด
    return _clamp(top / total * 100.0)


def risk_level(score: float) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


def assess(correlation: dict,
           min_events=DEFAULT_MIN_EVENTS,
           window_max=DEFAULT_WINDOW_MAX) -> RiskResult:
    """
    Entry point: รับ correlation pattern -> คืน RiskResult
    correlation = {src_ip, event_count, window_seconds, events}
    """
    events = correlation.get("events", [])

    S = factor_severity(events)
    F = factor_frequency(correlation.get("event_count", len(events)), min_events)
    T = factor_temporal(correlation.get("window_seconds", window_max), window_max)
    C = factor_target_concentration(events)

    R = (S * W_SEVERITY) + (F * W_FREQUENCY) + \
        (T * W_TEMPORAL) + (C * W_TARGET_CONCENTRATION)
    R = round(R, 2)

    return RiskResult(
        src_ip=correlation.get("src_ip", "unknown"),
        risk_score=R,
        risk_level=risk_level(R),
        factors={"S": S, "F": F, "T": T, "C": C},
    )