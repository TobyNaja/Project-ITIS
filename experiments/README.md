# experiments/ — ที่เก็บผลการทดลอง Phase 14 (T1–T11)

`results_template.csv` คือ **หัวตาราง 37 คอลัมน์ตาม Blueprint §14.5** (ไม่มีข้อมูลแถวใด ๆ)
คัดลอกไปเป็นไฟล์ผลของแต่ละรอบ แล้วกรอกจากหลักฐานจริงเท่านั้น

```
cp experiments/results_template.csv experiments/results_2026-XX-XX.csv
```

## ที่มาของแต่ละคอลัมน์ (ห้ามกรอกจากความจำ)

| กลุ่ม | คอลัมน์ | มาจาก |
|---|---|---|
| identity (5) | `test_id` | T1..T11 |
| | `run_id` | ตัวระบุของชั้นการทดลอง เช่น `T4-R03` — **ไม่ใช่ key ใน DB** |
| | `scenario` | ชื่อ scenario ตาม §14.4 (`scripts/generate_test_events.py --list`) |
| | `src_ip` | source ที่ใช้ยิง |
| | `expected_result` | §14.4 Expected — เขียนก่อนรัน ห้ามแก้ตามผลที่ออกมา |
| timestamps (7) | `t_event` `t_detection` `t_decision` `t_block_cmd` `t_block_verified` | `experiment_timestamps` (pipeline บันทึกตอนเหตุการณ์เกิด) |
| | `t_unblock` | `actions` ที่ `action='UNBLOCK'` |
| | `t_recovery` | `recovery_events.timestamp` ของ attempt ที่ `result='SUCCESS'` |
| latency (5) | `detection_latency_ms` | M1 = `t_detection − t_event` |
| | `decision_latency_ms` | M2 = `t_decision − t_detection` |
| | `enforcement_latency_ms` | M3 = `t_block_verified − t_decision` |
| | `end_to_end_latency_ms` | M4 = `t_block_verified − t_event` |
| | `recovery_time_ms` | `t_recovery − เวลาที่ health ตรวจเจอ DEGRADED` |
| risk (8) | `event_count` `max_severity` | `correlated_patterns` |
| | `severity_score` `frequency_score` `temporal_score` `context_score` `risk_score` `risk_level` | `risk_assessments` |
| decision (4) | `weight_set` | `risk_assessments.weight_set` (A/B/C) |
| | `rule_id` `decision` `allowlisted` | `decisions` |
| result (3) | `action_result` | `actions.command_result` |
| | `verify_result` | `actions.verify_result` |
| | `recovery_result` | `recovery_events.result` (SUCCESS/FAIL/CRITICAL) |
| resource (3) | `cpu_percent` `ram_percent` `pps` | **เว้นว่าง** จนกว่าจะมีค่าจาก monitoring จริง — ระบบไม่มี collector และจะไม่สร้างเพิ่มในเฟสนี้ |
| evidence (2) | `notes` | หมายเหตุของรอบนั้น |
| | `evidence_path` | path ของ screenshot/log ที่เก็บไว้ (`docs/evidence/T4/...`) |

## กติกา

- คอลัมน์ที่ยังไม่เกิดเหตุการณ์ (เช่น `t_block_verified` ของ T1) ให้ **เว้นว่าง** ห้ามใส่ 0
  หรือเวลาปัจจุบัน — ค่าว่างแปลว่า "ไม่เกิด" ส่วน 0 แปลว่า "เกิดและใช้เวลา 0 ms"
- `run_id` เป็น identifier ของชั้นการทดลอง เชื่อมกลับ DB ผ่าน
  `experiment_timestamps.notes` (`run=3`) เพราะ schema §3.4 ไม่มีคอลัมน์ repetition
- latency ทุกช่องคำนวณจาก timestamp ในตาราง ไม่ใช่จับเวลาด้วยมือ
- T1–T10 ทำอย่างน้อย 5 repetitions · T11 ทำ 3 รอบ (Set A/B/C) ด้วย pattern เดียวกัน

รายละเอียดขั้นตอนอยู่ใน `docs/test_plan.md`
