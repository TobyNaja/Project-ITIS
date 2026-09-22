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
"""
import time
import threading

from security_engine.models import CorrelationPattern
from security_engine.policy.source_context import UnknownSourceContextResolver
from security_engine.scoring.risk import calculate, DEFAULT_WEIGHT_SET
from security_engine.policy.rule_engine import BLOCK


class SecurityPipeline:
    def __init__(self, correlator, rule_engine, lifecycle,
                 lock=None, min_events=5, window_max=10.0, trace_sink=None,
                 source_context_resolver=None, weight_set=DEFAULT_WEIGHT_SET):
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

    def process(self, event) -> dict:
        """ประมวลผล 1 normalized event, คืน trace"""
        trace = {
            "src_ip": event.get("src_ip"),
            "event_time": event.get("timestamp"),      # Suricata clock — ห้ามใช้วัด latency
            "received_at": event.get("received_at"),    # SEC01 clock
            "t0_received": time.monotonic(),
            "t1_correlated": None,
            "t2_risk": None,
            "t3_decision": None,
            "t4_enforce_req": None,
            "t5_enforce_ok": None,
            "correlation_matched": False,
            "decision": None,                           # None = ยังไม่เข้า Rule Engine
        }

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
        trace["decision"] = decision.action

        # --- Enforce (เฉพาะ BLOCK) ---
        if decision.action == BLOCK:
            with self.lock:                             # กัน race กับ expire_due()
                trace["t4_enforce_req"] = time.monotonic()
                result = self.lifecycle.block(decision)
                if result.success:
                    trace["t5_enforce_ok"] = time.monotonic()
        # ALERT / NO_AUTO_BLOCK → log อย่างเดียว ไม่ enforce

        return self._emit(trace)

    def _emit(self, trace):
        """ส่ง trace ให้ sink (ถ้ามี) แล้วคืน trace — จุด return เดียวของ process()"""
        if self.trace_sink is not None:
            self.trace_sink(trace)
        return trace