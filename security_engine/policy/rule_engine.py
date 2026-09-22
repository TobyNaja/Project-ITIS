"""
security_engine/policy/rule_engine.py — Rule Engine (Blueprint §3.6)

Decision layer: รับ CorrelationPattern (+ RiskResult สำหรับ audit) แล้วตัดสิน Action เดียว:
    MONITOR / ALERT / BLOCK / NO_AUTO_BLOCK

*** ชั้นนี้ตัดสินใจอย่างเดียว ไม่สั่ง pfSense *** — enforce เป็นหน้าที่ของ lifecycle/enforcer

กฎทั้งหมดมาจาก config/rules.yaml (NFR-01) ไม่มี rule definition ซ้ำในไฟล์นี้:
    load_rules() -> RuleSet -> RuleEngine(rules, allowlist=...)
    priority น้อย = ประเมินก่อน, first match wins, ไม่ match = default_action

*** rule condition ห้ามอิง risk_level *** (§3.5 ระบุว่า risk level ใช้เพื่อ
dashboard/report ไม่ใช่ตัวตัดสิน block) — เงื่อนไขตัดสินจาก raw Suricata severity,
จำนวน event, ระยะเวลาของ pattern และสถานะ allowlist ของ source
RiskResult ยังถูกส่งเข้ามาเพื่อบันทึก score/level ลง Decision สำหรับ audit เท่านั้น
"""
from dataclasses import dataclass

from security_engine.models import CorrelationPattern
from security_engine.policy.rules_config import (   # re-export ให้ caller เดิมใช้ได้
    MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK, VALID_ACTIONS,
    Rule, RuleSet, RuleConfigError, load_rules,
)

DEFAULT_RULE_ID = "DEFAULT"


@dataclass
class Decision:
    action: str
    rule_id: str                # กฎที่ทำให้เกิด action นี้
    src_ip: str
    reason: str
    risk_level: str = ""        # audit/explainability เท่านั้น ไม่ใช่เงื่อนไขของกฎ
    risk_score: float = None    # audit/explainability เท่านั้น
    allowlisted: bool = False   # สถานะ allowlist ของ source ตอนตัดสิน (decisions.allowlisted)
    block_duration: int = 0     # >0 เฉพาะ BLOCK; lifecycle เอาไปใช้จริง

    def __str__(self):
        dur = f" ({self.block_duration}s)" if self.block_duration else ""
        return (f"[DECISION] {self.action}{dur} {self.src_ip} "
                f"[{self.rule_id}] level={self.risk_level} :: {self.reason}")


class RuleEngine:
    """ตัดสิน Action จาก CorrelationPattern ตาม RuleSet ที่ inject เข้ามา

    rules มาจาก load_rules() — RuleEngine ไม่แตะ filesystem เอง และไม่มี
    default hidden loading เพื่อให้ dependency ชัดเจน
    """

    def __init__(self, rules: RuleSet, allowlist=None):
        if not isinstance(rules, RuleSet):
            raise TypeError(
                "RuleEngine ต้องรับ RuleSet จาก load_rules() "
                f"ได้ {type(rules).__name__} — ดู config/rules.yaml")
        self.rules = rules
        # allowlist: set ของ src_ip ที่ห้าม auto-block (มาจาก load_allowlist())
        self.allowlist = set(allowlist) if allowlist else set()

    def decide(self, risk_result, correlation) -> Decision:
        """risk_result: RiskResult (ใช้ src_ip + เก็บ score/level ไว้ audit)
        correlation: CorrelationPattern (หรือ dict แบบเก่า)"""
        pattern = CorrelationPattern.from_dict(correlation)
        src_ip = getattr(risk_result, "src_ip", None) or pattern.src_ip
        level = getattr(risk_result, "risk_level", "")
        score = getattr(risk_result, "risk_score", None)
        allowlisted = src_ip in self.allowlist

        for rule in self.rules:
            if rule.matches(pattern, allowlisted):
                return Decision(
                    action=rule.action,
                    rule_id=rule.id,
                    src_ip=src_ip,
                    risk_level=level,
                    risk_score=score,
                    allowlisted=allowlisted,
                    block_duration=rule.block_duration_sec,
                    reason=self._reason(rule, pattern, allowlisted),
                )

        return Decision(
            action=self.rules.default_action,
            rule_id=DEFAULT_RULE_ID,
            src_ip=src_ip,
            risk_level=level,
            risk_score=score,
            allowlisted=allowlisted,
            reason=("ไม่เข้าเงื่อนไขของกฎใดเลย — ใช้ default action "
                    f"{self.rules.default_action}"),
        )

    @staticmethod
    def _reason(rule, pattern, allowlisted) -> str:
        """human-readable ตาม FR-14 — บอกว่ากฎไหน match เพราะอะไร"""
        parts = []
        for field, expected in rule.condition.items():
            if field == "source_in_allowlist":
                parts.append(f"allowlisted={allowlisted}")
            elif field == "min_severity":
                parts.append(f"severity={pattern.max_severity} (ต้อง ≤ {expected})")
            elif field == "min_same_src_events":
                parts.append(f"{pattern.event_count} events (ต้อง ≥ {expected})")
            elif field == "max_time_window_sec":
                parts.append(f"window={pattern.window_seconds}s (ต้อง ≤ {expected}s)")
        return f"[{rule.id}] " + " + ".join(parts)
