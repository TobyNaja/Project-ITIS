"""
analysis/plots.py — Phase 12.10 กราฟ (offline)

boxplot latency distribution จาก JSONL trace แยกเป็น 2 ภาพตาม scale ของ metric
เพราะ engine (ไมโครวินาที) กับ enforcement (ร้อยมิลลิวินาที) ต่างกัน ~10^5 เท่า
ภาพเดียวกันจะทำให้ engine แบนติดแกน 0 อ่านอะไรไม่ได้

  latency_boxplot_engine.png       Detection + Decision       หน่วย µs
  latency_boxplot_enforcement.png  Enforcement + End-to-End   หน่วย ms

หน่วยไม่ใช่ตัวเลือกของผู้ใช้ แต่เป็นคุณสมบัติของ metric group -> ไม่มี --unit

*** plot เฉพาะ record ที่ valid (BLOCK, latency ครบ, ไม่ติดลบ) ***
ใช้ validate() จาก analyze แหล่งเดียวกับที่คำนวณ summary — กราฟกับตัวเลขจึงตรงกันเสมอ

ใช้ matplotlib (ถ้าไม่มี: pip install matplotlib)

usage:
    python -m analysis.plots traces.jsonl --out docs/evidence/P12-ANALYSIS
"""
import argparse
import os

from analysis.analyze import load_jsonl, validate

# label = ชื่อ stage เท่านั้น (ไม่ระบุ t-diff บนแกน กันสับสน/ผิดทิศ)
# นิยาม latency จริงมาจาก compute_latencies() ใน trace_writer.py แหล่งเดียว
LABELS = {
    "detection_s":   "Detection",
    "decision_s":    "Decision",
    "enforcement_s": "Enforcement",
    "end_to_end_s":  "End-to-End",
}
ENGINE_STAGES = ("detection_s", "decision_s")
ENFORCEMENT_STAGES = ("enforcement_s", "end_to_end_s")

SCALE = {"us": 1e6, "ms": 1e3, "s": 1.0}
UNIT_LABEL = {"us": "µs", "ms": "ms", "s": "s"}


def make_boxplot(valid, out_path, stages, unit, title="ITIS Latency Distribution"):
    """สร้าง boxplot ของ stages ที่ระบุ; แปลงวินาที -> unit. คืน path ที่เขียน"""
    import matplotlib
    matplotlib.use("Agg")               # ไม่ต้องมี display (เขียนไฟล์อย่างเดียว)
    import matplotlib.pyplot as plt

    scale = SCALE[unit]
    data, labels = [], []
    for key in stages:
        vals = [r[key] * scale for r in valid if r.get(key) is not None]
        if vals:
            data.append(vals)
            labels.append(LABELS[key])

    if not data:
        raise ValueError(f"ไม่มีข้อมูล valid สำหรับ plot: {stages}")

    fig, ax = plt.subplots(figsize=(8, 5))
    try:
        ax.boxplot(data, tick_labels=labels, showmeans=True)
    except TypeError:  # matplotlib < 3.9 ไม่มี tick_labels (labels= โดนลบใน 3.11)
        ax.boxplot(data, labels=labels, showmeans=True)
    ax.set_ylabel(f"Latency ({UNIT_LABEL[unit]})")
    ax.set_title(f"{title}  (n={len(valid)} valid BLOCK trials)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def main():
    ap = argparse.ArgumentParser(
        description="Plot latency distributions from experiment JSONL.")
    ap.add_argument("jsonl")
    ap.add_argument("--out", default="docs/evidence/P12-ANALYSIS")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    records, _ = load_jsonl(args.jsonl)
    valid, invalid = validate(records)
    if not valid:
        print(f"ไม่มี valid record ({len(records)} total, {len(invalid)} invalid) — ไม่ plot")
        return

    for name, stages, unit, title in (
        ("latency_boxplot_engine.png", ENGINE_STAGES, "us",
         "ITIS Engine Latency (Detection + Decision)"),
        ("latency_boxplot_enforcement.png", ENFORCEMENT_STAGES, "ms",
         "ITIS Enforcement Latency (pfSense via SSH)"),
    ):
        path = make_boxplot(valid, os.path.join(args.out, name), stages, unit,
                            title=title)
        print(f"boxplot -> {path}  (n={len(valid)} valid, {len(invalid)} excluded)")


if __name__ == "__main__":
    main()
