"""
run_experiment.py — Phase 12 Synthetic Experiment Runner (mode: logic / enforcement)

ยิง scenario A1–A4 (synthetic EVE ป้อนเข้า pipeline ตรงๆ) ตามจำนวน trial
แล้วเขียน JSONL trace (ผ่าน TraceWriter) เพื่อให้ analyzer/plots ประมวลผล

*** ทุก trace มี input_mode="synthetic" *** — กันเอา synthetic ไปปนกับ real (Mode C)
*** Mode C (real Suricata) อยู่ในไฟล์แยก run_experiment_real.py — ไม่ปนกับตัวนี้ ***

Scenarios — decision มาจาก rules.yaml (raw Suricata severity ไม่ใช่ risk_level):
  A1  < min_same_src_events (4 events)  -> correlation ไม่ match -> decision=None
  A2  severity 2 (MEDIUM) × 5 ใน ≤10s   -> ALERT          (RULE-002)
  A3  severity 1 (HIGH) × 5 ใน ≤10s     -> BLOCK          (RULE-001)
  A4  allowlisted + severity 1          -> NO_AUTO_BLOCK  (RULE-003 priority 1)

*** ชื่อ A1–A4 เป็น internal label ***
mapping กับ test case ของ Blueprint: A1→T10 · A2→T3 · A3→T4 · A4→T5
รายงานต้องใช้ T-number เป็น canonical ID (ดู docs/blueprint-gap-matrix.md)

*** ทำไมไม่มี MONITOR scenario ***
MONITOR = default_action เมื่อไม่มีกฎใด match — หลัง STEP 3 เส้นทางนี้เกิดได้จริง
เช่น severity 3 (LOW) × 5 ที่ไม่เข้าเงื่อนไข min_severity ของ RULE-001/002
ตอนนี้ครอบด้วย unit test ของ RuleEngine (default path) ยังไม่ได้ทำเป็น scenario
ของ runner — จะจัดชุด T1–T11 ให้ครบใน STEP 10

--- Resilience (enforcement mode) ---
enforcement mode ยิง SSH -> pfSense จริง ซึ่งอาจ timeout เป็นครั้งคราว (GNS3/pfSense
ไม่เสถียร ไม่ใช่บั๊ก). runner จับ EnforcementError ต่อ trial แล้ว retry (--retries,
default 2) พร้อม delay 2 วิ ก่อนยอมแพ้ — ไม่ crash ทั้งรัน

trial_status ต่อ trace (dataset ครบทุก trial ไม่โกหกว่าผ่านตั้งแต่แรก):
  SUCCESS  + retry_count=0        -> ผ่านครั้งแรก
  SUCCESS  + retry_count>0        -> ผ่านหลัง retry (infra สะดุดแล้วหาย)
  FAILED   + retry_count=retries  -> retry หมดยังล้ม (infra failure จริง)
FAILED trace ไม่มี latency fields -> analyzer exclude เอง (ไม่เอา failed มาปนสถิติ)
แต่ยังนับให้เห็นใน validation report

Modes:
  logic       : synthetic EVE + FakeEnforcer (ไม่มี SSH, ไม่มี retry จำเป็น)
  enforcement : synthetic EVE + REAL PFSenseEnforcer -> pfSense (มี retry)

usage:
  python run_experiment.py --mode logic       --out traces_logic.jsonl --trials 3
  python run_experiment.py --mode enforcement --out traces_enf.jsonl   --trials 30 \
         --host admin@192.168.227.150 --retries 2
"""
import argparse
import threading
import time

from security_engine.correlation.engine import CorrelationEngine
from security_engine.policy.rule_engine import RuleEngine
from security_engine.policy.rules_config import load_rules
from security_engine.enforcement.pfsense_enforcer import PFSenseEnforcer, EnforcementError
from security_engine.lifecycle.block_store import BlockStore
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
from security_engine.pipeline import SecurityPipeline
from security_engine.experiment.trace_writer import TraceWriter

TEST_SRC = "198.51.100.77"   # TEST-NET (ไม่ใช่ Kali) สำหรับ enforcement mode
ALLOWLISTED_SRC = "203.0.113.9"

MIN_EVENTS = 5
WINDOW_MAX = 10.0
RETRY_DELAY_S = 2.0          # delay ก่อน retry (ให้ pfSense/GNS3 หายใจ)

SCENARIOS = ["A1", "A2", "A3", "A4"]


class FakeResult:
    def __init__(self, ok=True):
        self.success = ok
        self.command_ok = ok
        self.verified = ok
        self.status = "ENFORCED" if ok else "FAILED"


class FakeEnforcer:
    def add_block(self, ip): return FakeResult(True)
    def remove_block(self, ip): return FakeResult(True)
    def is_blocked(self, ip): return False
    def get_blocked_ips(self): return set()


def _events_now(src, dest_ips, severity):
    """สร้าง normalized events (timestamp = now, received_at = now)
    ใช้ event จริงในเวลาปัจจุบัน เพื่อให้ correlation window ใช้งานได้"""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return [{"src_ip": src, "dest_ip": d, "severity": severity,
             "timestamp": now.isoformat(), "received_at": now.isoformat()}
            for d in dest_ips]


# ---- scenario A1–A4 (synthetic) ----
# แต่ละอันคืน (events_to_feed, expected_decision) — ป้อนทีละ event เข้า pipeline
def scenario_events(scenario_id):
    if scenario_id == "A1":     # < min_events (4) -> correlation ไม่ match -> decision=None
        return _events_now(TEST_SRC, ["w", "x", "y", "z"], 1), None
    if scenario_id == "A2":     # MEDIUM -> ALERT (RULE-002: severity 2 = MEDIUM จริง)
        return _events_now(TEST_SRC, ["a", "b", "c", "d", "e"], 2), "ALERT"
    if scenario_id == "A3":     # HIGH -> BLOCK (RULE-001: severity 1 = HIGH)
        return _events_now(TEST_SRC, ["x"] * 5, 1), "BLOCK"
    if scenario_id == "A4":     # allowlisted -> NO_AUTO_BLOCK (RULE-003 มาก่อน)
        return _events_now(ALLOWLISTED_SRC, ["x"] * 5, 1), "NO_AUTO_BLOCK"
    raise ValueError(scenario_id)


def build(mode, host, db_path):
    correlator = CorrelationEngine(window_seconds=WINDOW_MAX, min_events=MIN_EVENTS)
    rule = RuleEngine(load_rules(), allowlist={ALLOWLISTED_SRC})
    enforcer = FakeEnforcer() if mode == "logic" else PFSenseEnforcer(host)
    store = BlockStore(db_path)
    lifecycle = BlockLifecycleManager(enforcer, store)
    lock = threading.Lock()
    pipeline = SecurityPipeline(correlator, rule, lifecycle, lock=lock,
                                min_events=MIN_EVENTS, window_max=WINDOW_MAX)
    return pipeline, enforcer, lifecycle


def _feed(pipeline, events):
    """ป้อน events ทั้งชุดเข้า pipeline คืน trace ตัวสุดท้าย
    *** อาจโยน EnforcementError (BLOCK trial + SSH ล้ม) — pipeline throw ทะลุมา ***
    ตอน throw pipeline ยังไม่ได้ return/emit trace ให้ (exception เด้งก่อน return)"""
    last_trace = None
    for ev in events:
        last_trace = pipeline.process(ev)
    return last_trace


def run_trial(mode, host, db_path, scenario_id, retries):
    """รัน 1 trial พร้อม retry เฉพาะ EnforcementError
    คืน (trace, expected) โดย trace มี trial_status/enforcement_ok/retry_count/error เสมอ

    - SUCCESS: trace จริงจาก pipeline (มี latency) + retry_count เท่าที่ retry ไป
    - FAILED : trace สังเคราะห์ (ไม่มี latency fields) เพราะ pipeline throw ก่อน emit
               -> analyzer จะ exclude เอง แต่ report เห็น infra failure"""
    events, expected = scenario_events(scenario_id)
    last_err = None

    for attempt in range(retries + 1):          # attempt 0 = ครั้งแรก, +retries = retry
        # correlator ใหม่ทุก attempt เพื่อไม่ให้ event ค้างข้าม attempt/trial
        pipeline, enforcer, lifecycle = build(mode, host, db_path)
        try:
            trace = _feed(pipeline, events)
            trace["input_mode"] = "synthetic"
            trace["trial_status"] = "SUCCESS"
            trace["enforcement_ok"] = (trace.get("decision") != "BLOCK"
                                       or trace.get("t5_enforce_ok") is not None)
            trace["retry_count"] = attempt
            trace["error"] = None

            # enforcement mode: ล้าง block ที่เพิ่งสร้าง (ไม่ทิ้ง state ค้างบน pfSense)
            if mode == "enforcement" and trace.get("decision") == "BLOCK":
                try:
                    enforcer.remove_block(TEST_SRC)
                except EnforcementError:
                    pass    # cleanup ล้มไม่กระทบผล latency ของ trial นี้
            return trace, expected

        except EnforcementError as e:
            last_err = str(e)
            if attempt < retries:
                print(f"  ! {scenario_id} attempt {attempt + 1} EnforcementError: "
                      f"{last_err} -> retry in {RETRY_DELAY_S}s", flush=True)
                time.sleep(RETRY_DELAY_S)
            # attempt สุดท้ายล้ม -> ตกลงไปสร้าง FAILED trace ข้างล่าง

    # retry หมดยังล้ม -> FAILED trace (ไม่มี latency fields เพราะ pipeline ไม่ emit ตอน throw)
    failed = {
        "src_ip": TEST_SRC,
        "input_mode": "synthetic",
        "decision": expected,               # เจตนา (แต่ enforcement ล้ม จึงไม่มี latency)
        "trial_status": "FAILED",
        "enforcement_ok": False,
        "retry_count": retries,
        "error": last_err,
        # ไม่ใส่ t0..t5 / latency ใดๆ -> analyzer จัดเป็น invalid (excluded) เอง
    }
    return failed, expected


def run(mode, out_path, trials, host, db_path, block_duration, retries):
    writer = TraceWriter(out_path, experiment={
        "mode": mode, "input_mode": "synthetic", "block_duration": block_duration,
        "retries": retries,
    })
    results = []

    for scenario_id in SCENARIOS:
        for trial in range(1, trials + 1):
            trace, expected = run_trial(mode, host, db_path, scenario_id, retries)
            writer.write(trace, scenario_id=scenario_id, trial_no=trial)

            status = trace["trial_status"]
            dec = trace.get("decision")
            ok = (status == "SUCCESS" and dec == expected)
            results.append((scenario_id, trial, dec, expected, status,
                            trace.get("retry_count", 0), ok))

            if status == "FAILED":
                print(f"{scenario_id} trial {trial}: FAILED "
                      f"(retry={trace['retry_count']}) error={trace['error']}",
                      flush=True)
            else:
                rc = trace.get("retry_count", 0)
                tag = "OK" if ok else "MISMATCH"
                extra = f" (recovered after {rc} retr{'y' if rc == 1 else 'ies'})" if rc else ""
                print(f"{scenario_id} trial {trial}: decision={dec} "
                      f"expected={expected} {tag}{extra}", flush=True)

    passed = sum(1 for r in results if r[6])
    failed = sum(1 for r in results if r[4] == "FAILED")
    recovered = sum(1 for r in results if r[4] == "SUCCESS" and r[5] > 0)
    print(f"\n=== {mode}: {passed}/{len(results)} decisions match | "
          f"{failed} infra-FAILED | {recovered} recovered-after-retry ===")
    print(f"traces -> {out_path}")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["logic", "enforcement"], required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--host", default="admin@192.168.227.150")
    ap.add_argument("--db", default="data/experiment.db")
    ap.add_argument("--block-duration", type=int, default=10,
                    help="experiment-only; ไม่กระทบ T0-T5")
    ap.add_argument("--retries", type=int, default=2,
                    help="retry เฉพาะ EnforcementError ต่อ trial (delay 2s ต่อครั้ง)")
    args = ap.parse_args()
    run(args.mode, args.out, args.trials, args.host, args.db,
        args.block_duration, args.retries)


if __name__ == "__main__":
    main()