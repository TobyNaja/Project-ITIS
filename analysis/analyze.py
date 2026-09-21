"""
analysis/analyze.py — Phase 12.10 Analyzer (offline 100%)

อ่าน JSONL trace -> validate -> filter -> คำนวณ latency -> summary CSV/JSON + validation report
*** ไม่แตะ pipeline / pfSense / lifecycle ***

หลักที่ล็อก:
- ไม่ silently drop: รายงาน records_total / valid / invalid / excluded เสมอ
- decision != BLOCK ห้ามปนกับ BLOCK latency
- t ที่ขาด / negative latency / scenario_id หาย -> invalid (นับไว้ ไม่กลืน)
- trial_no ซ้ำ (ต่อ scenario) -> flag
- ไม่คำนวณ accuracy/FPR/detection rate

usage:
    python -m analysis.analyze traces.jsonl --out docs/evidence/P12-ANALYSIS
"""
import argparse
import csv
import json
import os

from analysis.stats import summarize

# latency metric ที่ protocol ล็อก (ต้องมาจาก BLOCK trial ที่ครบ stage)
BLOCK_METRICS = ["detection_s", "decision_s", "enforcement_s", "end_to_end_s"]


def load_jsonl(path):
    """อ่านทีละบรรทัด -> (records, parse_errors)"""
    records, parse_errors = [], 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1
    return records, parse_errors


def validate(records):
    """แยก valid / invalid พร้อมเหตุผล — ไม่ทิ้งเงียบ
    valid = BLOCK trial ที่ latency ครบและไม่ติดลบ"""
    valid, invalid = [], []
    for r in records:
        reasons = []
        if not r.get("scenario_id"):
            reasons.append("missing scenario_id")
        if r.get("decision") != "BLOCK":
            reasons.append(f"decision={r.get('decision')} (not BLOCK)")
        # latency ต้องครบและไม่ติดลบ
        for m in BLOCK_METRICS:
            v = r.get(m)
            if v is None:
                reasons.append(f"{m} missing")
            elif v < 0:
                reasons.append(f"{m} negative ({v})")
        if reasons:
            invalid.append({"record": r, "reasons": reasons})
        else:
            valid.append(r)
    return valid, invalid


def find_duplicate_trials(valid):
    """flag (scenario_id, trial_no) ที่ซ้ำ"""
    seen, dups = set(), []
    for r in valid:
        key = (r.get("scenario_id"), r.get("trial_no"))
        if key in seen:
            dups.append(key)
        seen.add(key)
    return dups


def analyze(path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    records, parse_errors = load_jsonl(path)
    valid, invalid = validate(records)
    dups = find_duplicate_trials(valid)

    # สรุปสถิติต่อ metric (รวมทุก BLOCK valid; ถ้าต้องแยก scenario ทำเพิ่มได้)
    summary = {m: summarize([r.get(m) for r in valid]) for m in BLOCK_METRICS}

    # ---- validation report (ไม่ silently drop) ----
    report = [
        "=== Phase 12 Latency Validation Report ===",
        f"records_total    : {len(records)}",
        f"records_valid    : {len(valid)}",
        f"records_invalid  : {len(invalid)}",
        f"records_excluded : {len(invalid)}  (= invalid; non-BLOCK/missing/negative)",
        f"json_parse_errors: {parse_errors}",
        f"duplicate_trials : {len(dups)} {dups if dups else ''}",
        "",
        "หมายเหตุ: valid = BLOCK trial ที่ latency ครบทุก stage และไม่ติดลบเท่านั้น",
        "reasons ของ invalid:",
    ]
    for item in invalid:
        rid = item["record"].get("scenario_id"), item["record"].get("trial_no")
        report.append(f"  {rid}: {'; '.join(item['reasons'])}")
    report_txt = "\n".join(report)

    # ---- write outputs ----
    with open(os.path.join(out_dir, "validation_report.txt"), "w", encoding="utf-8") as f:
        f.write(report_txt + "\n")

    with open(os.path.join(out_dir, "latency_summary.json"), "w", encoding="utf-8") as f:
        json.dump({"counts": {"total": len(records), "valid": len(valid),
                              "invalid": len(invalid), "parse_errors": parse_errors},
                   "summary": summary}, f, indent=2, default=str)

    with open(os.path.join(out_dir, "latency_summary.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "n", "median", "q1", "q3", "iqr", "min", "max", "p95"])
        for m in BLOCK_METRICS:
            s = summary[m]
            w.writerow([m, s["n"], s["median"], s["q1"], s["q3"],
                        s["iqr"], s["min"], s["max"], s["p95"]])

    return {"summary": summary, "counts": {"total": len(records), "valid": len(valid),
            "invalid": len(invalid)}, "report": report_txt}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", help="path ของ trace JSONL")
    ap.add_argument("--out", default="docs/evidence/P12-ANALYSIS")
    args = ap.parse_args()
    result = analyze(args.jsonl, args.out)
    print(result["report"])
    print(f"\n-> outputs written to {args.out}/")


if __name__ == "__main__":
    main()