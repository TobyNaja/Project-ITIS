"""
security_engine/experiment/trace_writer.py — Phase 12.9 Trace Writer

เขียน trace เป็น JSONL (1 trace 1 บรรทัด) สำหรับงานวิจัย
ไม่พึ่ง terminal output — data ต้อง persist เพื่อคำนวณสถิติทีหลัง

trace ที่ pipeline คืน มี monotonic timestamp (t0..t5) ซึ่ง "เทียบข้าม process ไม่ได้"
-> trace_writer คำนวณ latency (ส่วนต่าง ภายใน trace เดียว) ให้เลย + แนบ metadata
ของ experiment (scenario_id, trial_no, block_duration ฯลฯ) ก่อนเขียน
"""
import json
import threading
from datetime import datetime, timezone


def compute_latencies(trace) -> dict:
    """คำนวณ latency แต่ละ stage จาก monotonic t0..t5 (หน่วย: วินาที)
    คืน None สำหรับ stage ที่ไม่ถึง (เช่น ไม่ BLOCK ก็ไม่มี enforcement latency)"""
    def diff(a, b):
        if trace.get(a) is None or trace.get(b) is None:
            return None
        return trace[b] - trace[a]

    return {
        "detection_s":    diff("t0_received", "t1_correlated"),
        "decision_s":     diff("t1_correlated", "t3_decision"),
        "enforcement_s":  diff("t4_enforce_req", "t5_enforce_ok"),
        "end_to_end_s":   diff("t0_received", "t5_enforce_ok"),
    }


class TraceWriter:
    """เขียน trace + latency + experiment metadata ลง JSONL (thread-safe)"""
    def __init__(self, path, experiment=None):
        self.path = path
        self.experiment = experiment or {}   # metadata คงที่ต่อ run (ดู ExperimentConfig)
        self._lock = threading.Lock()

    def write(self, trace, *, scenario_id=None, trial_no=None):
        record = {
            "logged_at": datetime.now(timezone.utc).isoformat(),
            "scenario_id": scenario_id,
            "trial_no": trial_no,
            # กฎเหล็ก: ทุก record ต้องมี input_mode ระดับ top-level
            # (กัน synthetic ปน real) — write() เลือก field เองจึงต้องยกมาใส่ตรงนี้
            # trace มาก่อน (run_experiment แนบก่อน write), ตกไปใช้ experiment metadata
            "input_mode": trace.get("input_mode") or self.experiment.get("input_mode"),
            # experiment params (block_duration ฯลฯ) เพื่อ reproduce ได้
            **{f"exp_{k}": v for k, v in self.experiment.items()},
            # trial outcome — ต้อง persist เพื่อรายงาน infra failure จาก JSONL
            # (write() เลือก field เอง; ไม่ยกมาใส่ตรงนี้ = หายตอนเขียนไฟล์)
            # FAILED trace ไม่มี latency fields -> analyzer exclude เองจาก trial_status
            "trial_status": trace.get("trial_status"),
            "enforcement_ok": trace.get("enforcement_ok"),
            "retry_count": trace.get("retry_count"),
            "error": trace.get("error"),
            # ผล decision + latency
            "src_ip": trace.get("src_ip"),
            "correlation_matched": trace.get("correlation_matched"),
            "decision": trace.get("decision"),
            "event_time": trace.get("event_time"),      # Suricata clock (ไม่ใช้วัด)
            "received_at": trace.get("received_at"),     # SEC01 clock
            **compute_latencies(trace),
        }
        line = json.dumps(record, default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return record

    def __call__(self, trace):
        # ให้ใช้เป็น trace_sink ตรงๆ ได้ (scenario/trial ผูกไว้ภายนอกถ้าต้องการ)
        return self.write(trace)