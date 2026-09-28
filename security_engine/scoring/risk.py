"""
security_engine/scoring/risk.py — Risk Model v1 (Blueprint §3.5 — ล็อกแล้ว)

รับ CorrelationPattern + SourceContext แล้วคืน RiskResult:
    R = (S × w_sev) + (F × w_freq) + (T × w_temp) + (C × w_ctx)
    ทุก factor normalize เป็น 0–100 ก่อน -> R ∈ [0, 100]

normalize table ห้ามเปลี่ยน (§3.5):
    S  severity 1→75, 2→50, 3→25, custom critical (0)→100
    F  1 event→20, 2–3→40, 4–5→70, >5→100
    T  ≤10s→100, ≤30s→75, ≤60s→50, >60s→25        (absolute lookup — ไม่ผูกกับ
                                                    correlation window ที่ config ไว้)
    C  allowlisted→0, known lab asset→30, unknown/external→80

*** Risk Engine ไม่สั่ง BLOCK *** — คืน score/level ให้ Rule Engine ตัดสินเอง
*** Risk Engine ไม่โหลด allowlist/asset list เอง *** — รับ SourceContext ที่ resolve
    มาแล้วเข้ามา (dependency injection) เพื่อให้ unit test ไม่ต้องแตะ filesystem
"""
from dataclasses import dataclass

from security_engine.models import CorrelationPattern, SourceContext

# ---- Weight Sets สำหรับ Sensitivity Analysis (§3.5 — ล็อกแล้ว) ----
WEIGHT_SETS = {
    "A": {"severity": 0.40, "frequency": 0.25, "temporal": 0.20, "context": 0.15},
    "B": {"severity": 0.30, "frequency": 0.30, "temporal": 0.25, "context": 0.15},
    "C": {"severity": 0.50, "frequency": 0.20, "temporal": 0.15, "context": 0.15},
}
DEFAULT_WEIGHT_SET = "A"

# ---- S: Severity map ----
#   0 = reserved ของโปรเจกต์สำหรับ custom critical signature -> 100
#       (ไม่ใช่การตีความ Suricata severity 0 = critical โดยอัตโนมัติ)
SEVERITY_SCORE = {0: 100.0, 1: 75.0, 2: 50.0, 3: 25.0}
UNKNOWN_SEVERITY_SCORE = 25.0       # severity นอกตาราง -> ให้คะแนนต่ำสุด ไม่ใช่สูงสุด

# ---- C: Context scores ----
CONTEXT_ALLOWLISTED = 0.0
CONTEXT_KNOWN_ASSET = 30.0
CONTEXT_UNKNOWN = 80.0

# ---- Risk Level (Experimental Classification Thresholds §3.5) ----
#   0–29 LOW | 30–59 MEDIUM | 60–79 HIGH | 80–100 CRITICAL
#   *** ใช้เพื่อ dashboard/รายงาน ไม่ใช่ตัวตัดสิน block ***
LEVEL_THRESHOLDS = (
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (30.0, "MEDIUM"),
    (0.0, "LOW"),
)


@dataclass(frozen=True)
class RiskResult:
    """ชื่อ field ตรงกับตาราง risk_assessments (§3.4) — STEP 5 เขียนลง DB ได้ตรง ๆ"""
    src_ip: str
    severity_score: float
    frequency_score: float
    temporal_score: float
    context_score: float
    weight_set: str
    risk_score: float
    risk_level: str

    @property
    def factors(self) -> dict:
        """shorthand สำหรับ log/debug — contract จริงคือ field ชื่อเต็มด้านบน"""
        return {
            "S": self.severity_score,
            "F": self.frequency_score,
            "T": self.temporal_score,
            "C": self.context_score,
        }

    def __str__(self):
        return (
            f"[RISK] {self.src_ip} R={self.risk_score:.1f} {self.risk_level} "
            f"(S={self.severity_score:.0f} F={self.frequency_score:.0f} "
            f"T={self.temporal_score:.0f} C={self.context_score:.0f} "
            f"set={self.weight_set})"
        )


# ---------- normalize functions (§3.5) ----------
def factor_severity(max_severity) -> float:
    """S: จาก severity ที่รุนแรงที่สุดของ pattern (Suricata เลขน้อย = รุนแรงกว่า)"""
    if max_severity is None:
        return 0.0
    return SEVERITY_SCORE.get(max_severity, UNKNOWN_SEVERITY_SCORE)


def factor_frequency(event_count) -> float:
    """F: tier ตามจำนวน event ใน window เดียวกัน — 1=20, 2–3=40, 4–5=70, >5=100"""
    if event_count is None or event_count <= 0:
        return 0.0
    if event_count == 1:
        return 20.0
    if event_count <= 3:
        return 40.0
    if event_count <= 5:
        return 70.0
    return 100.0


def factor_temporal(window_seconds) -> float:
    """T: lookup ตามระยะเวลาจริงของ pattern — ≤10s=100, ≤30s=75, ≤60s=50, >60s=25

    *** absolute ไม่ใช่สัดส่วนของ correlation window *** — ถ้า config window เป็น 30s
    แล้ว pattern กินเวลา 25s จะได้ 75 ตามตาราง ไม่ใช่ (1 − 25/30) × 100
    """
    if window_seconds is None:
        return 0.0
    if window_seconds <= 10.0:
        return 100.0
    if window_seconds <= 30.0:
        return 75.0
    if window_seconds <= 60.0:
        return 50.0
    return 25.0


def factor_context(source_context: SourceContext) -> float:
    """C: allowlist มาก่อน known asset เสมอ

    allowlisted = 0 ไม่ได้ทำให้ risk score เป็น 0 (กระทบแค่ 15% ของสูตรด้วย Set A)
    การยกเว้นการ block จริงเป็นหน้าที่ของ RULE-003 ที่ Rule Engine คนละชั้นกัน (D4)
    """
    if source_context is None:
        return CONTEXT_UNKNOWN
    if source_context.allowlisted:
        return CONTEXT_ALLOWLISTED
    if source_context.known_asset:
        return CONTEXT_KNOWN_ASSET
    return CONTEXT_UNKNOWN


def risk_level(score: float) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


# ---------- entry point ----------
def calculate(pattern: CorrelationPattern,
              source_context: SourceContext,
              weight_set: str = DEFAULT_WEIGHT_SET) -> RiskResult:
    """คำนวณ Risk Score ของ pattern ด้วย weight set ที่ระบุ

    weight_set ที่ไม่ใช่ A/B/C -> ValueError (ห้ามเงียบแล้ว fallback เป็น A
    เพราะ sensitivity analysis จะอ่านผลผิดโดยไม่มีใครรู้)
    """
    if weight_set not in WEIGHT_SETS:
        raise ValueError(
            f"weight_set ต้องเป็นหนึ่งใน {tuple(WEIGHT_SETS)} ได้ {weight_set!r}")
    weights = WEIGHT_SETS[weight_set]

    pattern = CorrelationPattern.from_dict(pattern)

    S = factor_severity(pattern.max_severity)
    F = factor_frequency(pattern.event_count)
    T = factor_temporal(pattern.window_seconds)
    C = factor_context(source_context)

    R = round(
        S * weights["severity"] + F * weights["frequency"]
        + T * weights["temporal"] + C * weights["context"],
        2,
    )

    return RiskResult(
        src_ip=pattern.src_ip,
        severity_score=S,
        frequency_score=F,
        temporal_score=T,
        context_score=C,
        weight_set=weight_set,
        risk_score=R,
        risk_level=risk_level(R),
    )
