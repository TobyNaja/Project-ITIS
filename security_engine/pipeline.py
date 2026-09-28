"""
security_engine/pipeline.py — Phase 11.2 SecurityPipeline

ประกอบ component ทั้งสาย แล้ว process ทีละ event:
    normalized event → correlation → risk → rule → (BLOCK) → lifecycle.block()

*** ไม่มี loop, ไม่มี thread, ไม่อ่าน event เอง ***
    - main thread (entry point) เป็นคนวน stream_events() แล้วป้อน process() ทีละตัว
    - LifecycleRunner (แยกไฟล์) เป็นคนเรียก expire_due()
    - Pipeline เป็นเจ้าของ lock (Phase 11 กำหนด concurrency; Manager ไม่ต้อง thread-aware)

คืน trace dict ต่อ event สำหรับ latency (Phase 12) + audit:
    correlation_matched, decision (None ถ้ายังไม่เข้า Rule Engine),
    t0..t5 (monotonic), event_time/received_at (แยก clock ตามที่ล็อก)

Audit persistence (STEP 5B) — เขียนผ่าน AuditRepository เท่านั้น ไม่มี SQL ในไฟล์นี้:
    event -> security_events -> correlated_patterns -> risk_assessments -> decisions
    ALERT / NO_AUTO_BLOCK -> actions.action = ALERT   (MONITOR ไม่ใช่ response action)
    BLOCK -> lifecycle.block() -> actions.action = BLOCK -> active_blocks.action_id

*** audit ต้องถูกบันทึกก่อน enforcement *** — ถ้า DB ล้มก่อนสั่ง pfSense จะยังไม่มี
firewall state ที่ต้องตามแก้ (ดู alignment plan STEP 5) และ AuditPersistenceError
ไม่ใช่ความล้มเหลวของ enforcement (NFR-06)
"""
import time
import threading
from datetime import datetime, timezone

from security_engine.models import CorrelationPattern
from security_engine.policy.source_context import UnknownSourceContextResolver
from security_engine.scoring.risk import calculate, DEFAULT_WEIGHT_SET
from security_engine.policy.rule_engine import BLOCK, ALERT, NO_AUTO_BLOCK


def _utc_iso(value=None):
    """wall-clock UTC ISO8601 (NFR-04) สำหรับ experiment_timestamps

    แยกคนละหน้าที่กับ time.monotonic():
        monotonic  -> วัดช่วงเวลา (ไม่กระโดดเมื่อ NTP ปรับนาฬิกา) = latency ที่เชื่อถือได้
        wall clock -> จุดเวลาที่บันทึกเป็นหลักฐานและ join กับ EVE/pfSense log ได้
    ทั้งคู่ถูกเก็บใน trace เดียวกัน ไม่ใช่ตัวใดตัวหนึ่งแทนอีกตัว
    """
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return str(value)


class SecurityPipeline:
    def __init__(self, correlator, rule_engine, lifecycle,
                 lock=None, min_events=5, window_max=10.0, trace_sink=None,
                 source_context_resolver=None, weight_set=DEFAULT_WEIGHT_SET,
                 repository=None):
        self.correlator = correlator
        self.rule_engine = rule_engine
        self.lifecycle = lifecycle
        # lock ตัวเดียวกับที่ LifecycleRunner ใช้ — Pipeline เป็นเจ้าของ concurrency
        self.lock = lock or threading.Lock()
        # min_events/window_max เป็นค่าของ CorrelationEngine — Risk Model v1 ไม่ใช้แล้ว
        # (factor T เป็น absolute lookup ตาม §3.5) เก็บไว้เพื่อไม่ให้ caller เดิมพัง
        self.min_events = min_events
        self.window_max = window_max
        # resolver ของ factor C — default = ถือว่าทุก source เป็น unknown/external
        # ต้องแทนด้วยตัวที่อ่าน asset list จริงใน STEP 2B
        self.source_context_resolver = (
            source_context_resolver or UnknownSourceContextResolver())
        self.weight_set = weight_set
        # trace_sink: callable(trace) optional — เขียน trace ลง JSONL สำหรับ experiment
        # default None = คืน trace เฉยๆ (test เดิมไม่กระทบ)
        self.trace_sink = trace_sink
        # repository: AuditRepository optional — None = ไม่บันทึก audit trail
        # (unit test ที่สนใจแค่ decision/latency ไม่ต้องมี DB)
        self.repository = repository

    def process(self, event) -> dict:
        """ประมวลผล 1 normalized event, คืน trace"""
        trace = {
            "src_ip": event.get("src_ip"),
            "event_time": event.get("timestamp"),      # Suricata clock — ห้ามใช้วัด latency
            "received_at": event.get("received_at"),    # SEC01 clock
            "t0_received": time.monotonic(),
            # --- wall-clock UTC ตามชื่อของ §3.4 experiment_timestamps (FR-15) ---
            # t_event มาจากนาฬิกาของ Suricata (pfSense) ส่วนที่เหลือเป็นนาฬิกาของ SEC01
            # -> M1 ข้าม clock domain ต้องมี NTP sync (Blueprint M1 ระบุ clock skew ไว้เอง)
            "t_event": _utc_iso(event.get("timestamp")) if event.get("timestamp")
                       else None,
            "t_detection": _utc_iso(event.get("received_at")),
            "t_decision": None,
            "t_block_cmd": None,
            "t_block_verified": None,
            "t1_correlated": None,
            "t2_risk": None,
            "t3_decision": None,
            "t4_enforce_req": None,
            "t5_enforce_ok": None,
            "correlation_matched": False,
            "decision": None,                           # None = ยังไม่เข้า Rule Engine
            "decision_id": None,                        # audit: decisions.id
            "action_id": None,                          # audit: actions.id
            "duplicate_block": False,                   # FR-11: ถูกระงับเพราะ block ซ้ำ
            "block_suppressed": False,                  # ไม่มีคำสั่งถูกส่งไป pfSense
        }

        # --- Ingestion audit (ต้องมาก่อน correlate: pattern ใช้ _db_id ของ event) ---
        if self.repository is not None:
            self.repository.save_security_event(event)

        # --- Correlation ---
        match = self.correlator.process(event)
        if not match:
            # ยังไม่ครบเกณฑ์ — ไม่เข้า Rule Engine, decision คง None
            return self._emit(trace)
        trace["correlation_matched"] = True
        trace["t1_correlated"] = time.monotonic()

        # --- Risk ---
        pattern = CorrelationPattern.from_dict(match)
        source_context = self.source_context_resolver.resolve(pattern.src_ip)
        risk = calculate(pattern, source_context, weight_set=self.weight_set)
        trace["t2_risk"] = time.monotonic()

        # --- Rule ---
        decision = self.rule_engine.decide(risk, pattern)
        trace["t3_decision"] = time.monotonic()
        trace["t_decision"] = _utc_iso()
        trace["decision"] = decision.action

        # --- Audit chain (ก่อน enforcement เสมอ) ---
        decision_id = None
        if self.repository is not None:
            pattern_id = self.repository.save_correlated_pattern(pattern)
            assessment_id = self.repository.save_risk_assessment(pattern_id, risk)
            decision_id = self.repository.save_decision(
                assessment_id, decision, allowlisted=decision.allowlisted)
            # ALERT และ NO_AUTO_BLOCK ต่างก็ "แจ้งเตือน" -> actions.action = ALERT
            # (schema §3.4 ไม่มี action type ชื่อ NO_AUTO_BLOCK)
            if decision.action in (ALERT, NO_AUTO_BLOCK):
                self.repository.save_alert_action(decision_id, decision.src_ip)
        trace["decision_id"] = decision_id

        # --- Enforce (เฉพาะ BLOCK) ---
        if decision.action == BLOCK:
            with self.lock:                             # กัน race กับ expire_due()
                trace["t4_enforce_req"] = time.monotonic()
                trace["t_block_cmd"] = _utc_iso()
                result = self.lifecycle.block(decision)
                if result.success:
                    trace["t5_enforce_ok"] = time.monotonic()
                    # verified แล้วเท่านั้น — ล้มเหลว/ถูกระงับ ต้องคง None ไว้
                    trace["t_block_verified"] = _utc_iso()
                trace["duplicate_block"] = getattr(result, "duplicate", False)
                trace["block_suppressed"] = getattr(result, "suppressed", False)

                # audit หลัง enforcement — บันทึกผลจริงของ pfSense ตามที่เกิดขึ้น
                # *** ห้ามแก้ผล enforcement เพราะ audit ล้ม *** (NFR-06):
                # ถ้า firewall block สำเร็จแล้ว state จริงยังเป็น BLOCKED เสมอ
                # AuditPersistenceError จะทะลุขึ้นไปให้ผู้เรียกเห็นว่า audit ล้ม
                # โดยที่ trace ยังบันทึก t5 (enforcement สำเร็จ) ไว้ตามความจริง
                self._audit_enforcement(trace, decision, decision_id, result)
        # ALERT / NO_AUTO_BLOCK → log อย่างเดียว ไม่ enforce

        return self._emit(trace)

    def _audit_enforcement(self, trace, decision, decision_id, result):
        """บันทึก actions ของ BLOCK แล้วผูกเข้า active_blocks

        - enforcement ล้ม -> ยังบันทึก action ตามความจริง (command/verify = FAIL)
          แต่ไม่ link เพราะ lifecycle ไม่ได้สร้าง active_blocks ให้ (ไม่มี fake success)
        - อยู่ใน lock เดียวกับ lifecycle.block() เพื่อกัน expire_due() ปลด block
          ไปก่อนที่จะ link ทัน
        """
        if self.repository is None or decision_id is None:
            return
        # suppressed = ไม่มีคำสั่งถูกส่งไป pfSense เลย (duplicate ACTIVE หรือค้าง
        # REMOVE_FAILED) -> ไม่มี action ให้บันทึก การบันทึกเป็น FAIL จะเป็นการ
        # โกหกว่าพยายาม enforce แล้วล้ม
        if getattr(result, "suppressed", False):
            return
        action_id = self.repository.save_enforcement_action(
            decision_id, result, duration_sec=decision.block_duration)
        trace["action_id"] = action_id
        if result.success:
            self.repository.link_active_block_action(decision.src_ip, action_id)

    def _emit(self, trace):
        """ส่ง trace ให้ sink (ถ้ามี) แล้วคืน trace — จุด return เดียวของ process()"""
        if self.trace_sink is not None:
            self.trace_sink(trace)
        return trace