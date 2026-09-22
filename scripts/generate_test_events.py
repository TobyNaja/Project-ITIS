"""
scripts/generate_test_events.py — STEP 10.3: controlled input สำหรับ T1–T11 (Phase 14)

    generate_test_events.py ──EVE JSON lines──> eve.json / stdin ──> eve_reader ──> engine

*** สคริปต์นี้สร้าง "input" อย่างเดียว ***
ไม่ตัดสิน MONITOR/ALERT/BLOCK, ไม่เขียน decision/enforcement/recovery ลงที่ไหนทั้งสิ้น
ผลการทดลองต้องมาจาก engine จริงเท่านั้น (Correlation -> Risk -> RuleEngine -> Pipeline)

`expected_result` ที่ติดมากับแต่ละ scenario คือ "สิ่งที่ Blueprint §14.4 คาดไว้"
สำหรับกรอกช่อง expected_result ใน results_template.csv — ไม่ใช่ผลที่วัดได้
ห้ามนำไปเขียนทับผลจริงไม่ว่ากรณีใด

รูปแบบ output = EVE JSON ของ Suricata (1 บรรทัด 1 event) เพื่อให้ผ่าน parser เดิมทั้งสาย
(parse_line -> normalize) ไม่ใช่ normalized dict ที่ข้ามขั้นตอน ingestion ไป

usage:
    python scripts/generate_test_events.py --test-id T4
    python scripts/generate_test_events.py --test-id T10 --variant b --run 3
    python scripts/generate_test_events.py --test-id T3 --out /tmp/t3.json
    python scripts/generate_test_events.py --list
"""
import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# ---- ค่าที่ใช้ทำการทดลอง (TEST-NET-2/3 ตาม RFC 5737 ไม่ชนเครือข่ายจริง) ----
DEFAULT_SRC = "198.51.100.77"           # TEST-NET-2: source ที่ไม่ได้ allowlist
ALLOWLISTED_SRC = "203.0.113.9"         # TEST-NET-3: ต้องตรงกับ config/allowlist.yaml
DEFAULT_DEST = "198.51.100.10"

# Suricata severity ดิบ (1=High, 2=Medium, 3=Low) — ห้ามแปลงเป็น risk level ที่นี่
SEV_HIGH = 1
SEV_MEDIUM = 2
SEV_LOW = 3

SIGNATURES = {
    SEV_HIGH: (2001219, "ET SCAN Potential SSH Scan"),
    SEV_MEDIUM: (2010935, "ET SCAN Suspicious inbound to mSQL port 4333"),
    SEV_LOW: (2100498, "GPL ATTACK_RESPONSE id check returned root"),
}

# ช่องไฟระหว่าง event ภายในหน้าต่าง correlation (10s) — 5 events ใช้เวลา ~4s
DEFAULT_SPACING_SEC = 1.0
STATS_INTERVAL_SEC = 8                  # ตรงกับ health.stats_interval_sec ใน config


@dataclass(frozen=True)
class Scenario:
    test_id: str
    name: str
    expected_result: str                # §14.4 Expected — ไม่ใช่ผลที่วัดได้
    alerts: int = 0                     # จำนวน alert ที่สร้าง
    severity: int = SEV_HIGH
    src_ip: str = DEFAULT_SRC
    stats: int = 0                      # จำนวน stats event (health/FR-02)
    manual_step: str = ""               # สิ่งที่ผู้ทดลองต้องทำเอง (generator ทำแทนไม่ได้)
    variants: tuple = field(default_factory=tuple)
    note: str = ""


# ---- T1–T11 ตาม Blueprint §14.4 (ห้ามคิด scenario ใหม่) ----
SCENARIOS = {
    "T1": Scenario("T1", "Normal Traffic", "MONITOR / No Block",
                   alerts=0, stats=3,
                   note="traffic ปกติ ไม่มี security alert — มีแต่ stats ของ Suricata"),
    "T2": Scenario("T2", "Single Medium Alert", "MONITOR / No Block",
                   alerts=1, severity=SEV_MEDIUM,
                   note="alert เดี่ยว ไม่ใช่ correlated attack pattern"),
    "T3": Scenario("T3", "Repeated Medium Alerts", "ALERT (RULE-002)",
                   alerts=5, severity=SEV_MEDIUM,
                   note="5 MEDIUM จาก source เดียวภายใน 10 วินาที"),
    "T4": Scenario("T4", "Critical Pattern", "BLOCK -> VERIFIED (RULE-001)",
                   alerts=5, severity=SEV_HIGH,
                   note="5 HIGH จาก source เดียวภายใน 10 วินาที และไม่ได้ allowlist"),
    "T5": Scenario("T5", "Allowlisted Critical Pattern",
                   "NO_AUTO_BLOCK + ALERT (RULE-003)",
                   alerts=5, severity=SEV_HIGH, src_ip=ALLOWLISTED_SRC,
                   note="pattern เดียวกับ T4 แต่ source อยู่ใน allowlist "
                        "— risk score ยังถูกคำนวณตามปกติ ไม่ใช่ 0"),
    "T6": Scenario("T6", "Auto-Unblock", "BLOCK -> 300s -> UNBLOCK -> EXPIRED",
                   alerts=5, severity=SEV_HIGH,
                   manual_step="รอจน expires_at (block.duration_sec) ผ่าน แล้วตรวจ "
                               "active_blocks.status = EXPIRED + actions.action = UNBLOCK",
                   note="input เหมือน T4 — ส่วนที่ทดสอบคือ lifecycle หลัง block"),
    "T7": Scenario("T7", "Enforcement Verification", "verify_result = VERIFIED",
                   alerts=5, severity=SEV_HIGH,
                   manual_step="ตรวจ read-back บน pfSense (pfctl/GUI) + traffic "
                               "verification ว่าถูก DROP จริง",
                   note="input เหมือน T4 — ส่วนที่ทดสอบคือ command success ≠ "
                        "enforcement success"),
    "T8": Scenario("T8", "Suricata Recovery", "DEGRADED -> restart -> HEALTHY",
                   alerts=0, stats=3,
                   manual_step="หยุด Suricata บนเครื่อง IDS (fault injection) หลัง "
                               "stats ชุดนี้ แล้วปล่อยให้ HealthRunner ตรวจเจอเอง",
                   note="stats ที่สร้างไว้คือ baseline ก่อนฉีด fault — generator "
                        "ไม่สร้าง recovery_events เอง ค่าต้องมาจาก engine"),
    "T9": Scenario("T9", "Recovery Failure", "FAIL x3 -> CRITICAL (ไม่มี attempt 4)",
                   alerts=0, stats=3,
                   manual_step="ทำให้ restart ล้มเหลว (เช่น restart_command ผิด/"
                               "binary ใช้ไม่ได้) แล้วหยุด Suricata",
                   note="ต้องยืนยันว่า recovery_events มี 3 แถว ไม่ใช่ 4"),
    "T10": Scenario("T10", "False Positive Simulation", "MONITOR / No Block",
                    alerts=1, severity=SEV_HIGH, variants=("a", "b"),
                    note="a = 1 HIGH alert · b = 4 HIGH ภายใน 10 วินาที "
                         "(ยังไม่ถึง min_events=5)"),
    "T11": Scenario("T11", "Sensitivity Analysis", "เทียบ Set A/B/C ด้วย pattern เดียวกัน",
                    alerts=5, severity=SEV_HIGH,
                    manual_step="รัน pattern เดียวกันซ้ำด้วย risk.weight_set = A, B, C "
                                "แล้วบันทึก S/F/T/C + risk_score + risk_level + decision",
                    note="weight set เป็น configuration ไม่ใช่ input — event ชุดเดิม"),
}

# variant ที่เปลี่ยน "จำนวน alert" เท่านั้น (ไม่เปลี่ยน severity/source)
VARIANT_ALERTS = {
    ("T10", "a"): 1,
    ("T10", "b"): 4,
}


def _fmt(dt) -> str:
    """timestamp แบบที่ Suricata เขียนจริง: 2026-09-22T12:00:00.000000+0000"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def alert_event(src_ip, dest_ip, severity, timestamp, index=0) -> dict:
    signature_id, signature = SIGNATURES[severity]
    return {
        "timestamp": _fmt(timestamp),
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 40000 + index,
        "dest_ip": dest_ip,
        "dest_port": 22 if severity == SEV_HIGH else 4333,
        "proto": "TCP",
        "alert": {
            "signature_id": signature_id,
            "signature": signature,
            "severity": severity,
            "category": "Attempted Information Leak",
        },
    }


def stats_event(timestamp, uptime) -> dict:
    """stats ของ Suricata — FR-02 ให้ส่งเข้า on_stats ไม่ใช่เข้า correlation"""
    return {
        "timestamp": _fmt(timestamp),
        "event_type": "stats",
        "stats": {"uptime": uptime, "capture": {"kernel_packets": 1000 + uptime}},
    }


def generate(test_id, *, variant=None, src_ip=None, start=None,
             spacing_sec=DEFAULT_SPACING_SEC):
    """คืน list ของ EVE event (dict) ตาม scenario — ไม่มีผลการตัดสินใด ๆ ปนมา"""
    if test_id not in SCENARIOS:
        raise ValueError(f"ไม่รู้จัก test_id {test_id!r} "
                         f"(รองรับ {', '.join(SCENARIOS)})")
    scenario = SCENARIOS[test_id]
    if variant is not None and variant not in scenario.variants:
        raise ValueError(f"{test_id} ไม่มี variant {variant!r} "
                         f"(มี {scenario.variants or 'ไม่มี'})")

    start = start or datetime.now(timezone.utc)
    source = src_ip or scenario.src_ip
    count = VARIANT_ALERTS.get((test_id, variant), scenario.alerts)

    events = []
    for i in range(scenario.stats):
        events.append(stats_event(start + timedelta(seconds=i * STATS_INTERVAL_SEC),
                                  uptime=60 + i * STATS_INTERVAL_SEC))
    for i in range(count):
        events.append(alert_event(source, DEFAULT_DEST, scenario.severity,
                                  start + timedelta(seconds=i * spacing_sec), index=i))
    return events


def describe(test_id, variant=None) -> str:
    s = SCENARIOS[test_id]
    lines = [f"{s.test_id} — {s.name}",
             f"  expected (Blueprint §14.4): {s.expected_result}"]
    if s.note:
        lines.append(f"  note: {s.note}")
    if s.manual_step:
        lines.append(f"  ต้องทำเอง: {s.manual_step}")
    if s.variants:
        lines.append(f"  variants: {', '.join(s.variants)}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="สร้าง EVE JSON สำหรับ test case T1–T11 (input อย่างเดียว)")
    ap.add_argument("--test-id", help="T1..T11")
    ap.add_argument("--variant", help="variant ของ scenario (เช่น T10 a/b)")
    ap.add_argument("--run", type=int, default=1,
                    help="เลข repetition (T1–T10 ต้องทำ 5 ครั้ง) — ใช้เป็น run_id "
                         "ของ results_template.csv เท่านั้น ไม่ได้ลง DB")
    ap.add_argument("--src-ip", help="override source IP")
    ap.add_argument("--out", help="เขียนลงไฟล์ (default: stdout)")
    ap.add_argument("--spacing", type=float, default=DEFAULT_SPACING_SEC,
                    help="ช่องไฟระหว่าง alert (วินาที) — ต้องอยู่ในหน้าต่าง correlation")
    ap.add_argument("--list", action="store_true", help="แสดง scenario ทั้งหมดแล้วออก")
    args = ap.parse_args(argv)

    if args.list:
        for test_id in SCENARIOS:
            print(describe(test_id))
            print()
        return 0

    if not args.test_id:
        ap.error("ต้องระบุ --test-id (หรือใช้ --list)")

    events = generate(args.test_id, variant=args.variant, src_ip=args.src_ip,
                      spacing_sec=args.spacing)
    lines = "".join(json.dumps(e) + "\n" for e in events)

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(lines)
    else:
        sys.stdout.write(lines)

    scenario = SCENARIOS[args.test_id]
    run_id = f"{args.test_id}-R{args.run:02d}"
    print(f"[{run_id}] {scenario.name}: {len(events)} EVE events", file=sys.stderr)
    if scenario.manual_step:
        print(f"[{run_id}] ต้องทำเอง: {scenario.manual_step}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
