# STEP 11 — Metrics M1–M10 และ T11 sensitivity

สร้างโดย `metrics_step11.py` เมื่อ 2026-09-25 21:59:34 +0700 · source of truth = `data/step11_experiment.db` · run binding = `docs/evidence/step11_runs.csv`

## M1–M4 Latency (ms) — จาก `experiment_timestamps`

นาฬิกาเดียว (SEC01) ทั้ง t_event และ t_detection…t_block_verified · M1 = EVE ingestion latency ไม่ใช่ packet detection · M3 แยกตาม §1.4: `t_block_cmd − t_decision` = ก่อนเรียก lifecycle.block() (รวมบันทึก decision) · `t_block_verified − t_block_cmd` = command round-trip + verification รวมกัน (แยกไม่ได้)

| Metric | กลุ่ม | n | mean | median | min | max | SD |
|---|---|---|---|---|---|---|---|
| M1 | primary T3+T4 | 10 | 910.4 | 903.3 | 833.2 | 966.3 | 43.5 |
| M1 | ทุก run ที่มีค่า (T3–T7, T11) | 28 | 925.4 | 931.7 | 833.2 | 1119.1 | 56.6 |
| M2 | primary T3+T4 | 10 | 69.2 | 60.4 | 57.2 | 118.1 | 20.8 |
| M2 | ทุก run ที่มีค่า (T3–T7, T11) | 28 | 67.1 | 60.4 | 52.4 | 118.1 | 15.0 |
| M3 (pre-block) | primary T4+T7 | 10 | 231.2 | 225.0 | 171.9 | 306.4 | 45.3 |
| M3 (pre-block) | ทุก run ที่มีค่า (T3–T7, T11) | 18 | 235.5 | 238.3 | 171.9 | 306.4 | 41.4 |
| M3 (cmd+verify) | primary T4+T7 | 10 | 411.9 | 382.7 | 325.4 | 733.7 | 116.1 |
| M3 (cmd+verify) | ทุก run ที่มีค่า (T3–T7, T11) | 18 | 399.3 | 380.5 | 325.4 | 733.7 | 86.9 |
| M3 total | primary T4+T7 | 10 | 643.1 | 617.8 | 526.9 | 971.7 | 126.0 |
| M3 total | ทุก run ที่มีค่า (T3–T7, T11) | 18 | 634.9 | 627.9 | 526.9 | 971.7 | 96.1 |
| M4 | primary T4 | 5 | 1593.4 | 1584.1 | 1513.4 | 1695.5 | 74.0 |
| M4 | ทุก run ที่มีค่า (T3–T7, T11) | 18 | 1650.3 | 1631.7 | 1503.2 | 2008.6 | 123.3 |

ต่อ test group:

| test | n | M1 mean | M2 mean | M3 total mean | M4 mean |
|---|---|---|---|---|---|
| T3 | 5 | 890.1 | 71.4 | — | — |
| T4 | 5 | 930.7 | 66.9 | 595.7 | 1593.4 |
| T5 | 5 | 882.8 | 57.8 | — | — |
| T6 | 5 | 936.6 | 70.0 | 628.7 | 1635.3 |
| T7 | 5 | 970.5 | 71.3 | 690.5 | 1732.3 |
| T11 | 3 | 952.4 | 63.6 | 617.6 | 1633.7 |

## M5–M10 Rates — จาก DB

| Metric | ขอบเขต | ผล | นิยามที่ใช้ |
|---|---|---|---|
| M5 Detection Success | T1–T4 (20 runs) | 55/55 = 100.0% | security_events จาก src ของ input / alert ที่ inject (T1 inject 0) · เกินคาด 0 |
| M5 (อ้างอิง) | ทุก run ที่ inject | 170/170 = 100.0% | เหมือนบน |
| M6 Automated Action Success | T4, T7 | 10/10 = 100.0% | BLOCK SUCCESS+VERIFIED / decision BLOCK |
| M6 (อ้างอิง) | T4, T6, T7, T11 | 18/18 = 100.0% | เหมือนบน |
| M7 False Positive (scenario) | T1, T2, T3, T10 (25 runs) | 0/25 = 0.0% | run ที่มี BLOCK action / non-block cases — ไม่ใช่ FP rate ทั่วไป |
| M8 Allowlist Safety | T5 | 5/5 = 100.0% | allowlisted ไม่ถูก block / allowlisted tests |
| M9 Auto-Unblock Success | T6 | 5/5 = 100.0% | UNBLOCK VERIFIED / block ที่หมดอายุ |
| M9 (อ้างอิง) | ทุก BLOCK (T4, T6, T7, T11) | 18/18 = 100.0% | active_blocks ที่ไม่ EXPIRED ตอนจบ: 0 |
| **M10 Recovery Success** | T8 (recoverable failure) | 5/5 = 100.0% | recovered / injected failures |
| **T9 Recovery Failure Handling** | T9 (intentional, restart_command=/usr/bin/false) | 5/5 = 100.0% | attempt 1 FAIL → 2 FAIL → 3 CRITICAL, rc=1 ทุก attempt, ไม่มี attempt 4 |
| M10 aggregate (supplementary) | T8+T9 | 5/10 = 50.0% | รวม intentional failure ของ T9 (ออกแบบให้กู้ไม่ได้) — **ไม่ใช่** ตัวแทนความสามารถ recover จาก failure ที่ recoverable |

| recovery time T8 (ms) | n | mean | median | min | max | SD |
|---|---|---|---|---|---|---|
| t_recovery − t_fault | 5 | 26357.0 | 26340.5 | 26275.2 | 26487.0 | 82.0 |

t_fault = เวลาที่ run_fault.sh สั่ง `suricata.sh stop` (นาฬิกา SEC01, อยู่ใน registry notes) · t_recovery = `recovery_events.timestamp` (SUCCESS)

## T11 Sensitivity — pattern เดียวกัน เปลี่ยนแค่ weight set

| run | set | S | F | T | C | risk_score | risk_level | rule | decision | block verified |
|---|---|---|---|---|---|---|---|---|---|---|
| T11-R01 | A | 75.0 | 70.0 | 100.0 | 80.0 | 79.5 | HIGH | RULE-001 | BLOCK | VERIFIED |
| T11-R02 | B | 75.0 | 70.0 | 100.0 | 80.0 | 80.5 | CRITICAL | RULE-001 | BLOCK | VERIFIED |
| T11-R03 | C | 75.0 | 70.0 | 100.0 | 80.0 | 78.5 | HIGH | RULE-001 | BLOCK | VERIFIED |

cross-check `results_step11.csv` (M1 ต่อ run เทียบกับ DB): ตรงทั้งหมด · runs = 58
