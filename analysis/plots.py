"""
analysis/plots.py — Phase 12.10 กราฟ (offline)

boxplot latency distribution ต่อ stage จาก JSONL trace
ใช้ matplotlib (ถ้าไม่มี: pip install matplotlib)

*** plot เฉพาะ record ที่ valid (BLOCK, latency ครบ, ไม่ติดลบ) ***
ตามเกณฑ์เดียวกับ analyze.validate — ไม่ plot ข้อมูลเสีย

usage:
    python -m analysis.plots traces.jsonl --out docs/evidence/P12-ANALYSIS
"""
import argparse
import os

from analysis.analyze import load_jsonl, validate

# label = ชื่อ stage เท่านั้น (ไม่ระบุ t-diff บนแกน กันสับสน/ผิดทิศ)
# นิยาม latency จริงมาจาก compute_latencies() ใน trace_writer.py แหล่งเดียว
STAGES = [
    ("detection_s", "Detection"),
    ("decision_s", "Decision"),
    ("enforcement_s", "Enforcement"),
    ("end_to_end_s", "End-to-End"),
]


def make_boxplot(valid, out_path, title="ITIS Latency Distribution", unit="ms"):
    """สร้าง boxplot; แปลงวินาที->ms ถ้า unit='ms'. คืน path ที่เขียน"""
    import matplotlib
    matplotlib.use("Agg")               # ไม่ต้องมี display (เขียนไฟล์อย่างเดียว)
    import matplotlib.pyplot as plt

    scale = 1000.0 if unit == "ms" else 1.0
    data, labels = [], []
    for key, label in STAGES:
        vals = [r[key] * scale for r in valid if r.get(key) is not None]
        if vals:
            data.append(vals)
            labels.append(label)

    if not data:
        raise ValueError("ไม่มีข้อมูล valid สำหรับ plot")

    fig, ax = plt.subplots(figsize=(9, 5))
    try:
        ax.boxplot(data, tick_labels=labels, showmeans=True)
    except TypeError:  # matplotlib < 3.9 ไม่มี tick_labels (labels= โดนลบใน 3.11)
        ax.boxplot(data, labels=labels, showmeans=True)
    ax.set_ylabel(f"Latency ({unit})")
    ax.set_title(f"{title}  (n={len(valid)} valid BLOCK trials)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--out", default="docs/evidence/P12-ANALYSIS")
    ap.add_argument("--unit", choices=["ms", "s"], default="ms")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    records, _ = load_jsonl(args.jsonl)
    valid, invalid = validate(records)
    if not valid:
        print(f"ไม่มี valid record ({len(records)} total, {len(invalid)} invalid) — ไม่ plot")
        return
    path = make_boxplot(valid, os.path.join(args.out, "latency_boxplot.png"),
                        unit=args.unit)
    print(f"boxplot -> {path}  (n={len(valid)} valid, {len(invalid)} excluded)")


if __name__ == "__main__":
    main()