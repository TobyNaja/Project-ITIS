# STEP 11 — Final dataset freeze (2026-09-25)

หลังจุดนี้ห้ามเพิ่ม/แก้ข้อมูลทดลอง · ไม่มี rerun

## Code revision ต่อช่วง

| ช่วง | runs | code baseline |
|---|---|---|
| T1–T10 | 55 | `236ce70` (experiment freeze เดิม) |
| T11 | 3 | `d0a346d` (`fix: pass configured risk.weight_set to pipeline`) |

มี implementation revision ระหว่างการทดลอง: ก่อน T11 พบว่า `run_phase4.py` log ค่า `risk.weight_set`
แต่ไม่ส่งเข้า `SecurityPipeline` (ทุก run คำนวณด้วย Set A) · T1–T10 ตั้ง `weight_set: "A"` ซึ่งตรงกับ default
จึงให้ผลเดียวกัน แต่ **ไม่ได้รันด้วย `d0a346d`** — ห้ามรายงานว่า T1–T11 ใช้ commit เดียวกัน

## Database

- ไฟล์: `data/step11_experiment.db` (gitignored) · archive: `step11_work/archive/step11_experiment_final_2026-09-25.db`
- `PRAGMA wal_checkpoint(TRUNCATE)` = (0, 0, 0) · `journal_mode=DELETE` (ไฟล์เดียว ไม่มี -wal/-shm)
- `PRAGMA integrity_check` = ok
- SHA-256 `d4ffe24457eb1e64723bd4b8c72a42bf6de81f9a074a3c0061a9a2087039b805` (ต้นฉบับ = archive)

| table | rows |
|---|---|
| security_events | 173 (inject 170 + background alert จริง 3: id 46, 122, 163) |
| correlated_patterns | 28 |
| risk_assessments | 28 |
| decisions | 28 |
| actions | 46 (ALERT 10 · BLOCK 18 · UNBLOCK 18) |
| active_blocks | 1 (PK = src_ip, EXPIRED) |
| recovery_events | 20 (T8 5 · T9 15) |
| experiment_timestamps | 28 |

- DRYRUN (`T4-R00`) ไม่อยู่ใน DB นี้ (archive แยกที่ `data/step11_dryrun2.db`) · แถวแรกของ DB = T2-R01
- validation: `step11_validation.md` (58/58 PASS) · metrics: `step11_metrics.md` · registry: `step11_runs.csv`
  · results: `experiments/results_step11.csv` (cross-check กับ DB ตรง)

## ข้อความที่ต้องใช้ในรายงาน (ตามหลักฐาน)

**M3** — `t_block_verified − t_block_cmd` เป็นเวลารวม command + verification เพราะ implementation
ปัจจุบัน timestamp สองขั้นตอนนี้แยกกันไม่ได้ (ห้ามเรียก "command latency")

**M10** — ค่าหลัก = T8 5/5 · T9 รายงานแยกเป็น Recovery Failure Handling 5/5 · aggregate T8+T9 5/10
เป็น supplementary เท่านั้น (รวม intentional failure)

**T9** — พิสูจน์ได้: 3 attempts ต่อ run, rc=1 ทุก attempt, attempt 3 = CRITICAL, ไม่มี attempt 4,
health loop ทำงานต่ออีก 7 รอบ · พิสูจน์ไม่ได้: การประมวลผล security event ระหว่าง CRITICAL
> The engine remained operational in the health loop after entering CRITICAL, but event-processing
> continuity during CRITICAL was not directly verified because no event was injected during this interval.

ข้อจำกัดเพิ่ม: attempt 1–3 เกิดติดกันภายใน < 1 s (ไม่มี backoff) · `failure_reason` มี stderr ของ SSH
(post-quantum warning) ปนแทนข้อความของ `/usr/bin/false` — rc=1 ยังยืนยัน failure ได้

**T11** — Under the tested input pattern, changing the weight set changed the numerical risk score and
risk classification (A 79.5 HIGH · B 80.5 CRITICAL · C 78.5 HIGH), but did not change the resulting
rule-based action; all three sets resulted in RULE-001 BLOCK with successful verification.
(sensitivity analysis ไม่ใช่ optimization — ไม่จัดอันดับ set)

**Clock** — Clock offset between SEC01 and pfSense was not reduced to near-zero. During the second
experimental set, the measured offset changed from +183.87 ms at the beginning to +162.58 ms at the end.
The direction differed from the drift observed in the first set. No timestamp compensation was applied.
(วันที่ 2 ไม่ได้ resync เพราะไม่มีสิทธิ์ admin · ชุด T2–T8 ไม่มี offset ท้ายชุด — ดู `step11_clock.md`)
