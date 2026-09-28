# STEP 11 — Dataset validation

สร้างโดย `validate_step11.py` เมื่อ 2026-09-25 21:59:34 +0700 · อ่านอย่างเดียวจาก `data/step11_experiment.db`, `docs/evidence/step11_runs.csv`, `experiments/results_step11.csv`

- DB integrity_check: ok
- registry 58 runs · results CSV 58 rows · คาด 58
- identity: run_id ครบตาม mapping §2 ไม่ซ้ำ · registry = CSV
- ช่วงเวลา engine ซ้อนกัน: ไม่มี
- แถว DB นอกช่วง run: ไม่มี · experiment_timestamps ผูก run ไม่ได้/ซ้ำ: ไม่มี
- active_blocks ที่ไม่ EXPIRED: ไม่มี

| run_id | ผล | หมายเหตุ |
|---|---|---|
| T1-R01 | PASS | — |
| T1-R02 | PASS | — |
| T1-R03 | PASS | — |
| T1-R04 | PASS | — |
| T1-R05 | PASS | — |
| T2-R01 | PASS | — |
| T2-R02 | PASS | — |
| T2-R03 | PASS | — |
| T2-R04 | PASS | — |
| T2-R05 | PASS | — |
| T3-R01 | PASS | — |
| T3-R02 | PASS | — |
| T3-R03 | PASS | — |
| T3-R04 | PASS | — |
| T3-R05 | PASS | — |
| T4-R01 | PASS | — |
| T4-R02 | PASS | — |
| T4-R03 | PASS | background alert (ไม่ใช่ input): id 46 sid 1000001 fe80:0000:0000:0000:0a27:3eef:3b0a:dd1b->ff02:0000:0000:0000:0000:0000:0000:0002 |
| T4-R04 | PASS | — |
| T4-R05 | PASS | — |
| T5-R01 | PASS | — |
| T5-R02 | PASS | — |
| T5-R03 | PASS | — |
| T5-R04 | PASS | — |
| T5-R05 | PASS | — |
| T6-R01 | PASS | — |
| T6-R02 | PASS | — |
| T6-R03 | PASS | — |
| T6-R04 | PASS | — |
| T6-R05 | PASS | — |
| T7-R01 | PASS | — |
| T7-R02 | PASS | — |
| T7-R03 | PASS | background alert (ไม่ใช่ input): id 122 sid 1000001 fe80:0000:0000:0000:0a27:3eef:3b0a:dd1b->ff02:0000:0000:0000:0000:0000:0000:0002 |
| T7-R04 | PASS | — |
| T7-R05 | PASS | — |
| T8-R01 | PASS | — |
| T8-R02 | PASS | — |
| T8-R03 | PASS | — |
| T8-R04 | PASS | — |
| T8-R05 | PASS | — |
| T9-R01 | PASS | — |
| T9-R02 | PASS | — |
| T9-R03 | PASS | — |
| T9-R04 | PASS | — |
| T9-R05 | PASS | — |
| T10-R01 | PASS | — |
| T10-R02 | PASS | — |
| T10-R03 | PASS | — |
| T10-R04 | PASS | — |
| T10-R05 | PASS | — |
| T10-R06 | PASS | — |
| T10-R07 | PASS | — |
| T10-R08 | PASS | — |
| T10-R09 | PASS | — |
| T10-R10 | PASS | — |
| T11-R01 | PASS | background alert (ไม่ใช่ input): id 163 sid 1000001 fe80:0000:0000:0000:0a27:3eef:3b0a:dd1b->ff02:0000:0000:0000:0000:0000:0000:0002 |
| T11-R02 | PASS | — |
| T11-R03 | PASS | — |

**สรุป: PASS**
