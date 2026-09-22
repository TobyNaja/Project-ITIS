# Test Plan — T1–T11 (Blueprint Phase 14)

เอกสารนี้คือ **experimental protocol** ของโครงงาน ใช้ canonical test ID `T1`–`T11`
ตาม Blueprint §14.4 เท่านั้น

ผลการทดลองทุกค่าต้องมาจากการรันจริง — ห้ามกรอกย้อนหลังจากความจำ และห้ามแก้
`expected_result` ให้ตรงกับผลที่ออกมา

> **หมายเหตุเรื่องชื่อเดิม (เขียนครั้งเดียว):** สคริปต์ Phase 12 ใช้ป้าย `A1`–`A4`
> ซึ่งตรงกับ `A1→T10 · A2→T3 · A3→T4 · A4→T5` ป้ายชุดนั้น **ปลดระวางแล้ว**
> เอกสาร/รายงานต่อจากนี้ใช้ T-number เป็นชื่อหลักอย่างเดียว

---

## 1. Prerequisites

| # | เงื่อนไข | เหตุผล |
|---|---|---|
| P1 | pfSense/Suricata และ SEC01 **synchronize clocks ด้วย UTC/NTP** ก่อนวัด latency | `t_event` มาจากนาฬิกา Suricata ส่วน `t_detection` มาจากนาฬิกา SEC01 — M1 คร่อมสอง clock domain ถ้านาฬิกาเหลื่อมกัน ค่า M1 จะผิดโดยไม่มีสัญญาณเตือน (Blueprint §14.1 M1 ระบุข้อจำกัดนี้ไว้เอง) |
| P2 | บันทึกค่า offset ของนาฬิกาทั้งสองเครื่องก่อน/หลังชุดการทดลอง | ใช้ประกอบการตีความ M1 ในรายงาน |
| P3 | `ITIS_PFSENSE_HOST`, `ITIS_EVE_PATH` ตั้งค่าครบ | `run_phase4.py` fail-fast ถ้าไม่ครบ (NFR-07) |
| P4 | `config/config.yaml` ตรงกับค่าที่จะรายงาน (`window_sec=10`, `min_events=5`, `block.duration_sec=300`, `weight_set=A`) | ค่าเหล่านี้ถูกอ้างในผลทุกตาราง |
| P5 | `health.restart_command` ถูกตั้งเป็นคำสั่ง restart ของ pfSense ที่ **ยืนยันจากเครื่องจริง** แล้ว | ถ้าเว้นว่าง `restart()` จะล้มเหลวเสมอ — T8 จะไม่มีทางผ่าน |
| P6 | `config/allowlist.yaml` มี `203.0.113.9` | จำเป็นสำหรับ T5 |
| P7 | DB ของการทดลองเป็นไฟล์แยกจากหลักฐาน Phase 12 | `data/experiment.db` เดิมเป็นหลักฐาน pre-freeze ห้ามเขียนทับ |

### ข้อจำกัดที่ต้องระบุในรายงาน

- ไม่มี **manual baseline** ให้เทียบ จึงรายงานได้แค่ค่าที่วัดได้ของระบบนี้
  **ห้าม** เขียนว่า "ลดเวลาตอบสนองได้ X%"
- 5 repetitions ใช้ยืนยันความสม่ำเสมอในห้องแล็บ **ไม่ใช่** statistical inference
- M5/M7 เป็นอัตราภายใต้ scenario ที่กำหนดไว้เท่านั้น ไม่ใช่ detection rate หรือ
  false positive rate ของระบบในสภาพแวดล้อมจริง

---

## 2. Repetitions

| ชุด | จำนวนรอบ | หมายเหตุ |
|---|---|---|
| T1–T10 | 5 repetitions ต่อ test | `run_id` = `T4-R01` … `T4-R05` |
| T11 | 3 รอบ (Weight Set A, B, C) | ใช้ pattern เดียวกันทุกรอบ เปลี่ยนแค่ `risk.weight_set` |

---

## 3. ขั้นตอนมาตรฐานของหนึ่ง repetition

```
1. เตรียม        ตรวจ P1–P7 · เคลียร์ active_blocks ที่ค้าง · จด run_id
2. สร้าง input   python scripts/generate_test_events.py --test-id <T> [--variant x] --run <n>
3. ป้อนเข้าระบบ  ให้ Suricata/EVE ส่งเข้า run_phase4.py (หรือ append เข้าไฟล์ EVE ที่ engine ตามอยู่)
4. สังเกตผล      อ่านจาก logs/engine.log + SQLite ไม่ใช่จากหน้าจอ generator
5. เก็บหลักฐาน   screenshot/pfctl output -> docs/evidence/<T>/R<nn>/
6. กรอก CSV      experiments/results_*.csv (37 คอลัมน์ ตาม experiments/README.md)
```

`scripts/generate_test_events.py` สร้าง **input อย่างเดียว** ไม่ตัดสินผล
decision/enforcement/recovery ทั้งหมดต้องมาจาก engine

---

## 4. Test Cases

### T1 — Normal Traffic
- **Input:** traffic ปกติ ไม่มี security alert (generator ส่งเฉพาะ stats event)
- **Expected:** `MONITOR` · ไม่มี block · health = HEALTHY
- **ตรวจ:** `active_blocks` ไม่มีแถวใหม่ · `decisions` ไม่มี BLOCK · `logs/engine.log` ไม่มี ERROR
- **Metrics:** M5, M7

### T2 — Single Medium Alert
- **Input:** 1 × MEDIUM (severity 2)
- **Expected:** `MONITOR` · ไม่มี block (alert เดี่ยวไม่ใช่ correlated pattern)
- **ตรวจ:** `correlated_patterns` ไม่มีแถวใหม่
- **Metrics:** M5, M7

### T3 — Repeated Medium Alerts
- **Input:** 5 × MEDIUM · source เดียวกัน · ภายใน 10 วินาที
- **Expected:** correlated pattern → `RULE-002` → `ALERT` · ไม่มี block
- **ตรวจ:** `decisions.decision='ALERT'` · `actions.action='ALERT'` · `active_blocks` ไม่เพิ่ม
- **Metrics:** M1, M2, M5, M7

### T4 — Critical Pattern
- **Input:** 5 × HIGH (severity 1) · source เดียวกัน · ภายใน 10 วินาที · ไม่อยู่ใน allowlist
- **Expected:** correlation → risk assessment → `RULE-001` → `BLOCK` → pfSense → `VERIFIED`
- **ตรวจ:** `actions.command_result='SUCCESS'` **และ** `verify_result='VERIFIED'` ·
  `active_blocks.status='ACTIVE'` พร้อม `action_id` ที่ผูกไว้
- **Metrics:** M1, M2, M3, M4, M5, M6

### T5 — Allowlisted Critical Pattern
- **Input:** pattern เดียวกับ T4 แต่ source = `203.0.113.9` (allowlisted)
- **Expected:** risk score **ถูกคำนวณตามปกติ (ไม่ใช่ 0)** → `RULE-003` → `NO_AUTO_BLOCK` + `ALERT` + audit
- **ตรวจ:** `decisions.allowlisted=1` · ไม่มี BLOCK action · pfSense ไม่มี rule ใหม่
- **Metrics:** M8
- **หมายเหตุ:** factor C ของ source ที่ allowlist = 0 ทำให้คะแนนต่ำลงแต่ไม่เป็นศูนย์
  (ต้องบันทึกค่าจริงที่ engine คำนวณ ไม่ใช่ค่าที่คาดไว้)

### T6 — Auto-Unblock
- **Input:** เหมือน T4 แล้วรอจนครบ `block.duration_sec` (300s)
- **Expected:** `BLOCK` → 300s → `UNBLOCK` → `VERIFY` → `active_blocks.status='EXPIRED'`
- **ตรวจ:** มีแถว `actions.action='UNBLOCK'` · pfSense ไม่มี rule นั้นแล้ว
- **Metrics:** M9
- **ต้องทำเอง:** รอจนหมดอายุจริง ห้ามแก้ `expires_at` ใน DB

### T7 — Enforcement Verification
- **Input:** เหมือน T4
- **Expected:** `verify_result='VERIFIED'` — พิสูจน์ว่า **command success ≠ enforcement success**
- **ตรวจ:** read-back บน pfSense (`pfctl -t <table> -T show` หรือ GUI) + ยิง traffic ทดสอบว่าถูก DROP
- **Metrics:** M6
- **ต้องทำเอง:** เก็บ screenshot ของ read-back และผล traffic test

### T8 — Suricata Recovery
- **Input:** หยุด Suricata บนเครื่อง IDS ระหว่างที่ engine ทำงานอยู่
- **Expected:** health check เห็น `DEGRADED` → restart → stats กลับมา → `HEALTHY`
- **ตรวจ:** `recovery_events` มีแถว `result='SUCCESS'` · `failure_reason` เป็น
  `PROCESS_DOWN` / `EVE_STALE` (หรือทั้งคู่คั่นด้วย `;`) · `logs/engine.log` มีบันทึกครบ
- **Metrics:** M10
- **บันทึกเพิ่ม:** เวลาที่ตรวจเจอ, attempt ที่สำเร็จ, recovery time

### T9 — Recovery Failure
- **Input:** ทำให้ restart ล้มเหลว (เช่นตั้ง `restart_command` ให้ใช้ไม่ได้) แล้วหยุด Suricata
- **Expected:** attempt 1 FAIL → 2 FAIL → 3 FAIL → `CRITICAL` + ALERT → **หยุด retry**
- **ตรวจ:** `SELECT COUNT(*) FROM recovery_events` ของเหตุการณ์นั้น = **3 ไม่ใช่ 4** ·
  แถวสุดท้าย `result='CRITICAL'` · engine ยังประมวลผล event ต่อได้ (ไม่ตาย)
- **Metrics:** M10
- **หมายเหตุ:** หลังเข้า CRITICAL แล้ว HealthRunner จะ latch สถานะไว้และไม่สั่ง restart
  ซ้ำจนกว่า functional health จะกลับมา HEALTHY — ต้องยืนยันว่าไม่มี infinite retry loop

### T10 — False Positive Simulation
- **Input:**
  - variant **a** — 1 × HIGH alert
  - variant **b** — 4 × HIGH ภายใน 10 วินาที (ยังไม่ถึง `min_events=5`)
- **Expected:** ทั้งสอง variant → `MONITOR` · ไม่มี block
- **ตรวจ:** `active_blocks` ไม่มีแถวใหม่ทั้งสองกรณี
- **Metrics:** M7
- **ขอบเขตการตีความ:** T10 พิสูจน์ว่า *severity สูงอย่างเดียว* หรือ *ความถี่ที่ยังไม่ถึง
  threshold* ไม่ทำให้เกิด block เท่านั้น **ไม่ใช่** ข้อพิสูจน์ว่าระบบมี false positive 0%

### T11 — Sensitivity Analysis
- **Input:** pattern เดียวกัน (5 × HIGH ภายใน 10 วินาที) รัน 3 รอบด้วย Weight Set A, B, C
- **บันทึกต่อรอบ:** `severity_score`, `frequency_score`, `temporal_score`,
  `context_score`, `risk_score`, `risk_level`, `decision`, `rule_id`
- **Expected:** risk score เปลี่ยนตาม weight set · ถ้า decision ยังเหมือนเดิม ให้รายงาน
  เป็น *sensitivity finding* ว่าการตัดสินใจถูกกำหนดโดยกฎ (rule-based) มากกว่าน้ำหนัก
- **Golden case ที่ใช้อ้างอิง:** S=75, F=70, T=100, C=80 → Set A = **79.5 (HIGH)**
  (มี regression test คุมค่านี้อยู่ใน `tests/test_risk.py` / `tests/test_sensitivity.py`)

---

## 5. Metrics → แหล่งข้อมูล

| Metric | นิยาม | อ่านจาก | test ที่เกี่ยวข้อง |
|---|---|---|---|
| M1 Detection Latency | `t_detection − t_event` | `experiment_timestamps` | T3, T4 |
| M2 Decision Latency | `t_decision − t_detection` | `experiment_timestamps` | T3, T4 |
| M3 Enforcement Latency | `t_block_verified − t_decision` | `experiment_timestamps` | T4, T7 |
| M4 End-to-End | `t_block_verified − t_event` | `experiment_timestamps` | T4 |
| M5 Detection Success Rate | detected / expected events | `security_events` | T1–T4 |
| M6 Automated Action Success | verified actions / required actions | `actions` | T4, T7 |
| M7 False Positive Rate (scenario) | unnecessary blocks / non-block cases | `active_blocks`, `decisions` | T1, T2, T3, T10 |
| M8 Allowlist Safety | allowlisted ที่ไม่ถูก block / allowlisted tests | `decisions` | T5 |
| M9 Auto-Unblock Success | unblocked สำเร็จ / blocks ที่หมดอายุ | `actions` (UNBLOCK), `active_blocks` | T6 |
| M10 Recovery Success Rate | recovered / injected failures | `recovery_events` | T8, T9 |

M3 แยกย่อยได้เป็น command round-trip (`t_block_cmd − t_decision`) และ
verification (`t_block_verified − t_block_cmd`) ตาม §14.1

---

## 6. Evidence

```
docs/evidence/
├── T1/R01..R05/
├── T2/ ...
...
└── T11/SetA, SetB, SetC/
```

ทุกโฟลเดอร์ควรมี: screenshot ของสิ่งที่ตรวจ, ส่วนของ `logs/engine.log` ที่เกี่ยวข้อง,
และ path นี้ถูกอ้างในคอลัมน์ `evidence_path` ของ CSV

หลักฐานของ Phase 12 (`docs/evidence/P12-*`) เป็นหลักฐาน **ก่อน freeze** คนละชุดกับ
Phase 14 — ห้ามรวมกันหรือเขียนทับ
