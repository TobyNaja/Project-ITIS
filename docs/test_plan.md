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
| P1 | พยายาม sync นาฬิกา SEC01 ก่อนเริ่มแต่ละชุดการทดลองตาม §1.1 | `t_event` มาจากนาฬิกา Suricata ส่วน `t_detection` มาจากนาฬิกา SEC01 — M1 คร่อมสอง clock domain (Blueprint §14.1 M1 ระบุข้อจำกัดนี้ไว้เอง) |
| P2 | วัดและบันทึก clock offset SEC01 ↔ pfSense ก่อน/หลังชุดการทดลองตาม §1.1 | ใช้ประกอบการตีความ M1/M4 ในรายงาน |
| P3 | `ITIS_PFSENSE_HOST`, `ITIS_EVE_PATH` ตั้งค่าครบ | `run_phase4.py` fail-fast ถ้าไม่ครบ (NFR-07) |
| P4 | `config/config.yaml` ตรงกับค่าที่จะรายงาน (`window_sec=10`, `min_events=5`, `block.duration_sec=300`, `weight_set=A`) | ค่าเหล่านี้ถูกอ้างในผลทุกตาราง |
| P5 | `health.restart_command` = `/usr/local/etc/rc.d/suricata.sh restart` (ยืนยันจากเครื่องจริง 2026-09-23) | ถ้าเว้นว่าง `restart()` จะล้มเหลวเสมอ — T8 จะไม่มีทางผ่าน |
| P6 | **เฉพาะช่วง T5:** เพิ่ม `192.168.2.10` (Kali) ใน `config/allowlist.yaml` ชั่วคราว แล้ว **ลบออกหลังจบ T5** และตรวจ `git diff` ว่าไม่มี IP ทดลองค้าง | T5 ใช้ allowlist.yaml เป็น source of truth (STEP 2B) — runner/generator ไม่ hardcode IP |
| P7 | `system.db_path` = `data/step11_experiment.db` (เริ่มว่าง) | แยก experimental data ออกจาก `data/experiment.db` ที่เป็นหลักฐาน pre-freeze + lab validation ของ STEP 9 — ห้ามเขียนทับ ห้าม copy ข้อมูลข้าม |
| P8 | ถ้าแก้ configuration ของ Suricata (GUI หรือไฟล์) ต้อง restart Suricata และตรวจว่า PID เปลี่ยน ก่อนถือว่า configuration ใหม่มีผล | GUI Save ของ pfSense ไม่ restart process — config บนดิสก์ถูกแต่พฤติกรรมยังเป็นของเก่า (พบซ้ำใน lab) |

### 1.1 Clock protocol (ทุกชุดการทดลอง)

```
ก่อนชุด   1. Admin CMD: w32tm /resync
          2. w32tm /query /status          -> บันทึกผล sync (สำเร็จ/ล้มเหลว + Last Successful Sync Time)
          3. w32tm /stripchart /computer:192.168.227.150 /samples:5 /dataonly
             -> บันทึก offset_before_ms (min/max/mean), เวลาเริ่มชุด, test IDs ในชุด
ทดลอง
หลังชุด   4. stripchart 5 samples อีกครั้ง -> บันทึก offset_after_ms (min/max/mean)
```

- ค่าบวกของ stripchart = SEC01 ช้ากว่า pfSense
- `w32tm /resync` ล้มเหลว -> **ไม่ troubleshoot เพิ่ม** บันทึกเป็น observation/limitation แล้วทดลองต่อ
- ไม่ tune NTP เพิ่ม · **ไม่ชดเชย offset ใน code และไม่หัก offset ออกจาก latency อัตโนมัติ**
- แหล่งของ `t_event` ขึ้นกับ input mode (§1.2):

  | Mode | `t_event` มาจาก | M1 / M4 |
  |---|---|---|
  | **Primary: controlled EVE injection** (T1–T11) | timestamp ที่ generator ใส่ใน event — นาฬิกา SEC01 | **same-host** (SEC01 -> pfSense eve.json -> SSH tail -> SEC01) |
  | Supplementary: real Kali traffic | timestamp ที่ Suricata เขียน — นาฬิกา pfSense | **cross-host** — offset เป็น potential systematic error |

- ใน primary dataset clock offset เป็น **contextual evidence** ไม่ใช่ correction factor ของ M1/M4
- M2/M3 ใช้ same-host timestamps (engine process เดียวบน SEC01) ทุก mode
- baseline ก่อน freeze (2026-09-23 23:38:55–23:39:03 +07): offset +81.47 … +81.65 ms (mean +81.52 ms)
  หลังคืน `MaxAllowedPhaseOffset = 1` · drift ที่สังเกตได้ ≈ 1.1 ms/นาที

### 1.2 Input mode (protocol amendment ก่อน STEP 11)

**Primary dataset (T1–T11) = controlled raw EVE injection**

```
python scripts/generate_test_events.py --test-id <T> [--variant x] --run <n> --spacing 0   | ssh <ITIS_PFSENSE_HOST> 'cat >> /var/log/suricata/suricata_em224404/eve.json'
```

- `--spacing 0` บังคับ: event ทั้ง pattern ใช้ timestamp เดียวกัน (default 1.0 s ทำให้ event หลัง ๆ
  มี `t_event` ล้ำอนาคตเพราะถูก append พร้อมกัน -> M1 ติดลบ / M4 สั้นลง ~4 s)
  **ข้อจำกัด:** เป็น burst ภายใน window ≤10 s (factor T = 100 ตาม model) ไม่ได้จำลอง event ที่กระจาย
  ตลอด 10 วินาที
- M1 = **EVE event ingestion/detection latency** (`t_detection − t_event`, `t_event` = timestamp ใน
  injected event) — **ไม่ใช่** packet -> Suricata detection latency
- M4 = **controlled event -> verified enforcement latency** (`t_block_verified − t_event`)
- **T1 ไม่ inject อะไรเลย** — ใช้ stats จริงของ Suricata (ห้าม inject stats ปลอม เพราะปนกับ health signal
  ที่ใช้ `stats.uptime`) แล้วตรวจว่าไม่มี decision/action และ health = HEALTHY
- synthetic runner (`run_experiment.py`, อยู่ที่ root ของ repo) ต้องระบุ
  `--db data/step11_experiment.db` ทุกครั้ง (default ของ runner ชี้ `data/experiment.db`)
- **Supplementary validation** (real Kali traffic -> Suricata -> engine) แยกจาก dataset หลัก
  ใช้ยืนยันว่า pipeline รับ alert ที่ Suricata สร้างจริงได้ — ไม่รวมใน results ของ T1–T11

**DRYRUN-T4 (pre-experiment runtime validation — ไม่ใช่ T4 run)**

1. engine ใช้ `data/step11_experiment.db` · เริ่มด้วย `--test-id T4 --run-id T4-R00` (§1.4 — `R00` สงวนไว้ให้ DRYRUN)
   · inject T4 (`198.51.100.77`, `--spacing 0`)
   · ผ่านเมื่อ `experiment_timestamps` มี **1 แถว** ครบ 5 จุด และเรียงเวลาถูก
2. ตรวจครบ: ingestion -> correlation -> risk -> RULE-001 -> BLOCK -> pfSense -> VERIFIED + timestamps
3. ปล่อย engine ทำงานจน block หมดอายุและ UNBLOCK (ไม่ทิ้ง block ค้างบน pfSense)
4. หยุด engine · `ls -la data/step11_experiment.db*` · checkpoint/close SQLite ให้เรียบร้อย
5. archive ทั้งชุดเป็น `data/step11_dryrun2.db` (รอบ 2 — `step11_dryrun.db` คือรอบ 1 ห้ามเขียนทับ ห้าม `rm`)
   -> `step11_experiment.db` เริ่มว่างสำหรับ T1
6. ผล DRYRUN-T4 **ไม่เข้า** ชุดผลของ T4 × 5

### 1.3 Freeze rule (ตั้งแต่เริ่ม T1)

ห้ามเปลี่ยน: risk weights · rule thresholds · correlation window · block duration ·
allowlist logic · DB schema · timestamp protocol — เว้นแต่พบ bug ที่ทำให้ระบบไม่ตรง Blueprint จริง
ซึ่งต้อง **หยุด experiment -> แก้ + test + commit -> บันทึกการแก้ -> เริ่มชุดที่ได้รับผลใหม่**
ห้ามเอาผลก่อนและหลังแก้มาปนกัน

### 1.4 Runtime engine ต่อ run (FR-15 `experiment_timestamps`)

```
python run_phase4.py --test-id T4 --run-id T4-R03
```

- **1 process = 1 run** — identity (`test_id` + `run_id`) ผูกกับ `ExperimentTimestampSink`
  ตลอดอายุ process · restart engine ทุก run และรอ log `เริ่มอ่าน EVE จาก ...` ก่อน inject
- `--test-id` ต้องเป็น `T1`–`T11` · `--run-id` ต้องเป็นรูป canonical **`<test-id>-R<NN>`** เท่านั้น
  (prefix ต้องตรงกับ `--test-id`, NN สองหลัก) · ต้องระบุคู่กัน — ผิดรูปแบบ (เช่น `3`, `T3-R03`
  ภายใต้ `--test-id T4`) = engine ออกทันที (exit 2) **ก่อน** อ่าน config หรือแตะ pfSense
- run_id มีรูปเดียวทั้ง DB (`notes`) และ CSV — ไม่มีการแปลงภายหลัง:

  ```
  generator  --run 3
      ↓
  runtime    --run-id T4-R03
      ↓
  DB notes / CSV run_id = T4-R03
  ```
- ไม่ระบุ `--test-id` = production mode -> `trace_sink=None` -> ไม่เขียน `experiment_timestamps`
- ค่าเวลาทุกจุดคัดลอกจาก trace เดียวกับที่ pipeline ใช้ตัดสินใจ — ไม่สร้างเวลาใหม่
  และไม่ประกอบย้อนหลังจากตารางอื่น (`actions.timestamp` ≠ `t_block_cmd`)
- `notes` = `run=<run_id>; mode=injection; decision=<D>; suppressed=<0|1>`

| สถานการณ์ | แถว FR-15 |
|---|---|
| BLOCK + verified (T4/T7) | 1 แถว ครบ 5 จุด |
| ALERT / NO_AUTO_BLOCK / MONITOR ที่ correlation match (T3/T5) | 1 แถว · `t_block_cmd`, `t_block_verified` = NULL |
| correlation ไม่ match (T2, T10a/b) · T1 ไม่มี alert | **ไม่มีแถว** — ไม่มี decision stage ให้บันทึก (หลักฐานคือ `security_events` และไม่มี `decisions`) |
| block verify ล้ม | `t_block_cmd` มี · `t_block_verified` = NULL |
| block ถูกระงับ (duplicate ACTIVE / REMOVE_FAILED) | `t_block_cmd` = **NULL** + `suppressed=1` แม้ trace ภายในจะมี `t_block_cmd` (ตั้งไว้ก่อนเรียก `lifecycle.block()`) — FR-15 หมายถึงคำสั่งที่ส่งไป pfSense จริงเท่านั้น |
| sink บันทึกลง DB ไม่สำเร็จ | ไม่มีแถว · log ERROR · engine ทำงานต่อ (NFR-06) |

**ข้อจำกัด FR-15 ที่ต้องระบุในรายงาน**

- exception ก่อน `_emit()` (`EnforcementError` จาก `add_block()` หรือ `AuditPersistenceError`
  จาก `_audit_enforcement()`) -> sink ไม่ถูกเรียก -> **ไม่มีแถว FR-15** ของ trace นั้น
  (ยอมรับตาม decision 6a — ไม่แก้ `pipeline.py` เพื่อสร้างแถว)
- `add_block()` ส่งคำสั่งและ verify ในครั้งเดียว -> `t_block_cmd` คือเวลา **ก่อน** เรียก
  `lifecycle.block()` จึง **แยก command round-trip ออกจาก verification ไม่ได้** —
  `t_block_verified − t_block_cmd` = ทั้ง command + verification ไม่ใช่ verification อย่างเดียว

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
| T1–T10 | 5 repetitions ต่อ test | `run_id` = `T4-R01` … `T4-R05` (canonical §1.4) |
| T11 | 3 รอบ (Weight Set A, B, C) | ใช้ pattern เดียวกันทุกรอบ เปลี่ยนแค่ `risk.weight_set` |

---

## 3. ขั้นตอนมาตรฐานของหนึ่ง repetition

```
1. เตรียม        ตรวจ P1–P8 · clock protocol §1.1 (ต้นชุด) · เคลียร์ active_blocks ที่ค้าง · จด run_id
   เริ่ม engine  python run_phase4.py --test-id <T> --run-id <T>-R<nn> (process ใหม่ทุก run §1.4)
                 -> รอ log "เริ่มอ่าน EVE จาก ..." ก่อน inject
2. สร้าง input   python scripts/generate_test_events.py --test-id <T> [--variant x] --run <n> --spacing 0
3. ป้อนเข้าระบบ  append เข้า eve.json บน pfSense ที่ run_phase4.py tail อยู่ (§1.2) · T1 ไม่ inject
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
- **Input:** pattern เดียวกับ T4 แต่ source = `192.168.2.10` (Kali) ที่ใส่ใน allowlist ชั่วคราวตาม P6
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

§14.1 แยก M3 เป็น command round-trip กับ verification แต่ในระบบนี้ `add_block()` ส่งคำสั่ง
และ verify ในครั้งเดียว จึงแยกสองส่วนนี้ไม่ได้ (§1.4): `t_block_cmd − t_decision` = ช่วงก่อนเรียก `lifecycle.block()`
(รวมการบันทึก decision ลง DB) ไม่ใช่ command round-trip และ
`t_block_verified − t_block_cmd` = command round-trip + verification รวมกัน

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
