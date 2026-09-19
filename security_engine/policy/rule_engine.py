"""
security_engine/policy/rule_engine.py — Phase 6 Rule Engine

Decision layer: รับ RiskResult (จาก Phase 5) + correlation pattern (จาก Phase 4)
แล้วตัดสิน Action เดียว: MONITOR / ALERT / BLOCK / NO_AUTO_BLOCK

*** ชั้นนี้ตัดสินใจอย่างเดียว ไม่สั่ง pfSense ***
การ enforce จริง (pfsense_enforcer) เป็น Phase 8 หลัง Phase 0.5 เคลียร์

ลำดับกฎ (allowlist-first — สำคัญมาก):
  RULE-003  allowlisted source                                  -> NO_AUTO_BLOCK
  RULE-001  risk_level ∈ {HIGH, CRITICAL} + ≥min_events + ≤10s   -> BLOCK
            + not allowlisted
  RULE-002  risk_level == MEDIUM + ≥min_events + ≤10s            -> ALERT
  default                                                        -> MONITOR

หมายเหตุ: RULE-001 ใช้ "HIGH หรือสูงกว่า" เพื่อไม่ให้ CRITICAL หลุด
Risk Engine ยังเป็นแค่ input — ไม่มี `risk_score >= X -> BLOCK` แอบใส่
"""
from dataclasses import dataclass

# ---- Action constants ----
MONITOR = "MONITOR"
ALERT = "ALERT"
BLOCK = "BLOCK"
NO_AUTO_BLOCK = "NO_AUTO_BLOCK"

# ---- เกณฑ์ที่ล็อกไว้ (ต้องตรงกับ Correlation / Risk config) ----
DEFAULT_MIN_EVENTS = 5
DEFAULT_MAX_WINDOW = 10.0        # วินาที; กฎ "≤10s"

# risk_level ที่ถือว่า "HIGH หรือสูงกว่า"
_HIGH_OR_ABOVE = frozenset({"HIGH", "CRITICAL"})
BLOCK_DURATION = 300            # วินาที (ตามกฎ 300s) — ส่งต่อให้ Phase 8 ใช้


@dataclass
class Decision:
    action: str
    rule_id: str                # กฎที่ทำให้เกิด action นี้
    src_ip: str
    reason: str
    risk_level: str = ""
    block_duration: int = 0     # >0 เฉพาะ BLOCK; Phase 8 เอาไปใช้จริง

    def __str__(self):
        dur = f" ({self.block_duration}s)" if self.block_duration else ""
        return (f"[DECISION] {self.action}{dur} {self.src_ip} "
                f"[{self.rule_id}] level={self.risk_level} :: {self.reason}")


class RuleEngine:
    """ตัดสิน Action จาก RiskResult + correlation pattern (ไม่ enforce)"""

    def __init__(self, allowlist=None,
                 min_events=DEFAULT_MIN_EVENTS,
                 max_window=DEFAULT_MAX_WINDOW):
        # allowlist: set ของ src_ip ที่ห้าม auto-block (รับ set เข้ามาตรงๆ)
        self.allowlist = set(allowlist) if allowlist else set()
        self.min_events = min_events
        self.max_window = max_window

    def _meets_correlation_gate(self, correlation) -> bool:
        """เช็คเงื่อนไขร่วมของ RULE-001/002: ≥min_events และ ≤max_window"""
        count = correlation.get("event_count", 0)
        window = correlation.get("window_seconds", float("inf"))
        return count >= self.min_events and window <= self.max_window

    def decide(self, risk_result, correlation) -> Decision:
        """
        risk_result: RiskResult (มี src_ip, risk_level)
        correlation: dict (มี event_count, window_seconds)
        """
        src_ip = risk_result.src_ip
        level = risk_result.risk_level

        # ---- RULE-003: allowlist มาก่อนเสมอ ----
        if src_ip in self.allowlist:
            return Decision(
                action=NO_AUTO_BLOCK, rule_id="RULE-003", src_ip=src_ip,
                risk_level=level,
                reason="source อยู่ใน allowlist — ยกเว้นการ auto-block",
            )

        gate = self._meets_correlation_gate(correlation)

        # ---- RULE-001: HIGH หรือสูงกว่า + ผ่าน gate ----
        if gate and level in _HIGH_OR_ABOVE:
            return Decision(
                action=BLOCK, rule_id="RULE-001", src_ip=src_ip,
                risk_level=level, block_duration=BLOCK_DURATION,
                reason=(f"{level} + {correlation.get('event_count')} events "
                        f"ใน {correlation.get('window_seconds')}s + not allowlisted"),
            )

        # ---- RULE-002: MEDIUM + ผ่าน gate ----
        if gate and level == "MEDIUM":
            return Decision(
                action=ALERT, rule_id="RULE-002", src_ip=src_ip,
                risk_level=level,
                reason=(f"MEDIUM + {correlation.get('event_count')} events "
                        f"ใน {correlation.get('window_seconds')}s"),
            )

        # ---- default: MONITOR ----
        return Decision(
            action=MONITOR, rule_id="DEFAULT", src_ip=src_ip,
            risk_level=level,
            reason="ไม่เข้ากฎ BLOCK/ALERT — เฝ้าดูต่อ",
        )