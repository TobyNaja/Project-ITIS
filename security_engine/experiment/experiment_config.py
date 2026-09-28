"""
security_engine/experiment/experiment_config.py — Phase 12.9 Experiment Config

ค่าที่ล็อกสำหรับการทดลอง (แยกจาก production default ของระบบ)
บันทึกลง trace ทุกบรรทัด เพื่อให้ reproduce + defend ได้

*** 10s เป็น experiment-only parameter สำหรับ latency trial เท่านั้น ***
    ไม่แก้ค่าหลักของระบบ (production block_duration ยังเป็น 300s)
"""
from dataclasses import dataclass, asdict

# NOTE (Blueprint alignment, STEP 1): ค่าคงที่ด้านล่างซ้ำกับ config/config.yaml
# (correlation.window_sec / correlation.min_events / block.duration_sec) โดยตั้งใจ
# — configuration alignment ของสาย experiment จะทำใน STEP 10 ตาม
# docs/blueprint-alignment-plan.md ไม่ใช่ความซ้ำที่หลุดโดยไม่รู้ตัว

# ---- production default (ค่าจริงของระบบ ห้ามแก้เพื่อ experiment) ----
PROD_BLOCK_DURATION = 300
CORRELATION_WINDOW = 10        # min_events window (ล็อก)
MIN_EVENTS = 5                 # ล็อก


@dataclass
class ExperimentConfig:
    name: str
    block_duration: int             # production=300; latency experiment=10
    correlation_window: int = CORRELATION_WINDOW
    min_events: int = MIN_EVENTS
    trials: int = 1
    note: str = ""

    def to_meta(self) -> dict:
        return asdict(self)


# ---- config ที่ล็อกไว้ตาม protocol ----

# Functional: 3 trials/scenario, block_duration ปกติ 300s
FUNCTIONAL = ExperimentConfig(
    name="functional",
    block_duration=PROD_BLOCK_DURATION,   # 300s จริง
    trials=3,
    note="Functional verification A1-A5, B1-B3. 3 trials/scenario = confirm "
         "deterministic, NOT statistical inference.",
)

# Latency: 30 trials, duration สั้น 10s (experiment-only; ไม่กระทบ T0-T5)
LATENCY = ExperimentConfig(
    name="latency_block",
    block_duration=10,                    # experiment-only, บันทึกใน trace
    trials=30,
    note="30 trials = practical sample size for characterising latency "
         "distribution under lab conditions; reports central tendency + spread, "
         "NOT statistical inference to other systems. duration=10s is an "
         "experiment-only parameter (does not affect measured T0-T5); production "
         "block_duration stays 300s.",
)