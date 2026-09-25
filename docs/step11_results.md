# STEP 11 — Results, Findings และ Limitations (สำหรับบท Results ของรายงาน)

แหล่งข้อมูล: dataset ที่ freeze แล้ว (commit `8d31ae7`) — `data/step11_experiment.db`
(SHA-256 `d4ffe244…9b805`), `docs/evidence/step11_runs.csv`, `experiments/results_step11.csv`,
`docs/evidence/step11_metrics.md`, `docs/evidence/step11_dataset_freeze.md` · ไม่มีการแก้ dataset หรือ rerun

Code revision: T1–T10 = `236ce70` · T11 = `d0a346d` (ดูหัวข้อ Limitations L7)

---

## 1. Test Results (T1–T11, 58 runs)

Input ทุก test (ยกเว้น T1, T8, T9) = controlled EVE injection จาก `generate_test_events.py`
src `198.51.100.77` (T5 = `192.168.2.10` ที่ใส่ใน allowlist ชั่วคราว)

| Test | Scenario | Expected | Actual (ทุก run) | Runs | Outcome |
|---|---|---|---|---|---|
| T1 | Normal traffic (ไม่ inject) | MONITOR / no block | ไม่มีแถวใหม่ในตาราง audit ใด ๆ · pf table ว่าง · HEALTHY ตลอด | 5 | 5/5 PASS |
| T2 | 1 × MEDIUM | MONITOR / no block | security_events +1 · correlation ไม่ match → ไม่มี decision/action | 5 | 5/5 PASS |
| T3 | 5 × MEDIUM ภายใน 10 s | ALERT (RULE-002) | RULE-002 ALERT · risk 69.5 HIGH · action ALERT = NOT_APPLICABLE · ไม่มี block | 5 | 5/5 PASS |
| T4 | 5 × HIGH ภายใน 10 s | BLOCK → VERIFIED (RULE-001) | RULE-001 BLOCK · risk 79.5 HIGH · BLOCK SUCCESS + VERIFIED · UNBLOCK VERIFIED หลังหมดอายุ | 5 | 5/5 PASS |
| T5 | 5 × HIGH จาก allowlisted source | NO_AUTO_BLOCK (RULE-003) | RULE-003 NO_AUTO_BLOCK · allowlisted = 1 · C = 0 · risk 67.5 HIGH · ไม่มี BLOCK | 5 | 5/5 PASS |
| T6 | Block expiry | BLOCK → 300 s → UNBLOCK → EXPIRED | UNBLOCK VERIFIED ที่ 300.4–301.3 s หลัง block verified · pf table ว่างหลังจบ | 5 | 5/5 PASS |
| T7 | Enforcement verification | verify_result = VERIFIED | engine read-back VERIFIED · pfctl read-back @+10 s พบ IP ใน table (5/5) · traffic verification = NOT AVAILABLE (L6) | 5 | 5/5 PASS (read-back) |
| T8 | Suricata หยุด (restart ปกติ) | DEGRADED → restart → HEALTHY | DEGRADED (PROCESS_DOWN) → attempt 1 SUCCESS · Suricata PID ใหม่ + stats uptime reset · HEALTHY กลับมา | 5 | 5/5 PASS |
| T9 | Suricata หยุด + restart ใช้ไม่ได้ | 3 attempts → CRITICAL, ไม่มี attempt 4 | attempt 1 FAIL → 2 FAIL → 3 CRITICAL · rc=1 ทุก attempt · ไม่มี attempt 4 · latch CRITICAL 7 รอบ | 5 | 5/5 PASS |
| T10a | 1 × HIGH | MONITOR / no block | security_events +1 · ไม่มี decision/action · pf 0/0 | 5 | 5/5 PASS |
| T10b | 4 × HIGH ภายใน 10 s | MONITOR / no block | security_events +4 (< min_events 5) · ไม่มี decision/action · pf 0/0 | 5 | 5/5 PASS |
| T11 | 5 × HIGH, weight set A/B/C | risk เปลี่ยนตาม weight set | ดูหัวข้อ 3 · RULE-001 BLOCK VERIFIED ทุก set | 3 | บันทึกครบ 3/3 (ไม่มี pass/fail — sensitivity) |

หมายเหตุ:
- "MONITOR" ใน T1/T2/T10 = ไม่มีแถว decision (correlation ไม่ match ไม่สร้างแถว — นิยาม 4a ที่ล็อกไว้)
- background alert จริงจาก network (sid 1000001, IPv6 fe80 → ff02::2) 3 แถว ใน T4-R03, T7-R03, T11-R01
  ไม่ใช่ input ของ test และไม่ถูกนับในผล
- `active_blocks` มี PK = src_ip → ประวัติ block/unblock ของ T4/T6/T7/T11 อ่านจากตาราง `actions`

---

## 2. Metric Results

| Metric | ขอบเขต | Result | หมายเหตุ |
|---|---|---|---|
| M1 Detection Latency | T3+T4, n=10 | mean **910.4 ms** (median 903.3, 833.2–966.3) | EVE ingestion latency (t_detection − t_event) ไม่ใช่ packet detection |
| M2 Decision Latency | T3+T4, n=10 | mean **69.2 ms** (median 60.4, 57.2–118.1) | t_decision − t_detection |
| M3 Enforcement Latency (รวม) | T4+T7, n=10 | mean **643.1 ms** (median 617.8, 526.9–971.7) | t_block_verified − t_decision · **ไม่ใช่ pure command latency** |
| ├ ก่อนเรียก block | T4+T7, n=10 | mean 231.2 ms (median 225.0, 171.9–306.4) | t_block_cmd − t_decision (รวมการบันทึก decision ลง DB) |
| └ command + verification | T4+T7, n=10 | mean 411.9 ms (median 382.7, 325.4–733.7) | t_block_verified − t_block_cmd — แยกสองขั้นไม่ได้ |
| M4 End-to-End Latency | T4, n=5 | mean **1593.4 ms** (median 1584.1, 1513.4–1695.5) | t_block_verified − t_event |
| M5 Detection Success | T1–T4 | **55/55** (100%) | alert ที่ inject ถูกบันทึกใน security_events |
| M6 Automated Action Success | T4, T7 | **10/10** (100%) | BLOCK SUCCESS + VERIFIED / decision BLOCK |
| M7 False Positive (scenario-defined) | T1, T2, T3, T10 | **0/25** (0%) | block ที่ไม่ควรเกิด / non-block cases — **ไม่ใช่** FP rate ทั่วไป |
| M8 Allowlist Safety | T5 | **5/5** (100%) | allowlisted source ไม่ถูก block |
| M9 Auto-Unblock Success | T6 | **5/5** (100%) | UNBLOCK VERIFIED / block ที่หมดอายุ (ทุก block ใน dataset 18/18) |
| M10 Recovery Success | T8 | **5/5** (100%) | failure ที่ออกแบบให้กู้ได้ · recovery time mean 26,357 ms (26,275–26,487) |
| T9 Recovery Failure Handling | T9 | **5/5** | FAIL → FAIL → CRITICAL, ไม่มี attempt 4 — รายงานแยกจาก M10 |
| M10 aggregate (supplementary) | T8+T9 | 5/10 | รวม intentional failure ของ T9 — ไม่ใช่ตัวแทนความสามารถ recover |
| T11 Sensitivity | Set A / B / C | risk **79.5 / 80.5 / 78.5** | ดูหัวข้อ 3 |

ค่า latency อ้างอิงจากทุก run ที่มี timestamp (T3–T7, T11) อยู่ใน `docs/evidence/step11_metrics.md`
(M1 n=28 mean 925.4 ms · M4 n=18 mean 1650.3 ms)

Recovery time (T8) = `recovery_events.timestamp` (SUCCESS) − เวลาที่สั่ง `suricata.sh stop` (นาฬิกา SEC01)
รวมช่วงที่ health check ตรวจเจอ (check interval 15 s) + restart + รอ stats ใหม่

---

## 3. T11 Sensitivity

| Weight set | S | F | T | C | Risk score | Risk level | Rule | Decision | Enforcement |
|---|---|---|---|---|---|---|---|---|---|
| A | 75 | 70 | 100 | 80 | 79.5 | HIGH | RULE-001 | BLOCK | VERIFIED |
| B | 75 | 70 | 100 | 80 | 80.5 | CRITICAL | RULE-001 | BLOCK | VERIFIED |
| C | 75 | 70 | 100 | 80 | 78.5 | HIGH | RULE-001 | BLOCK | VERIFIED |

Under the tested input pattern, changing the weight set changed the numerical risk score and risk
classification, but did not change the resulting rule-based action; all three sets resulted in RULE-001
BLOCK with successful verification.

นี่คือ sensitivity analysis ไม่ใช่ optimization — ไม่จัดอันดับว่า set ใดดีกว่า

---

## 4. Findings

**F1 — ตอบ Research Question:** ภายใต้ controlled network environment และ predefined rules
ระบบสามารถ correlate IDS events (Suricata EVE) แล้วนำไปสู่ predefined firewall response บน pfSense
พร้อม verification และ lifecycle management (block → หมดอายุ → unblock) ได้ครบทุก run ที่คาดให้ block
(M6 10/10, M9 5/5) และวัด latency ได้จริงตลอดสาย event → detection → decision → enforcement verification
(M4 mean 1593.4 ms ใน T4)

**F2 — Latency breakdown:** ส่วนที่ใช้เวลามากที่สุดคือ EVE ingestion (M1 ~910 ms) รองลงมาคือ
command + verification บน pfSense (~412 ms) · การตัดสินใจภายใน engine (M2) ใช้ ~69 ms

**F3 — Decision safety ภายใต้ scenario ที่กำหนด:** ไม่มี block ที่ไม่ควรเกิดใน non-block cases (M7 0/25)
และ allowlisted source ไม่ถูก block (M8 5/5) · ผลนี้จำกัดอยู่ใน scenario ที่ทดสอบ ไม่ใช่ข้อพิสูจน์ว่า
ระบบมี false positive 0%

**F4 — Health/recovery:** เมื่อ Suricata หยุดและ restart ได้ ระบบกู้คืนได้ครั้งแรกทุก run (M10 5/5,
~26.4 s) · เมื่อ restart ใช้ไม่ได้ ระบบหยุด retry ที่ 3 attempts และเข้า CRITICAL โดยไม่มี infinite
retry loop (T9 5/5)

**F5 — Sensitivity:** weight set เปลี่ยน risk score และ risk level แต่ไม่เปลี่ยน action ใน pattern ที่ทดสอบ
→ การตัดสินใจถูกกำหนดโดยกฎ (rule-based) · เป็นผลเชิงโครงสร้าง: เงื่อนไขใน `config/rules.yaml`
ไม่อิง risk_level/risk_score (§3.5 — ใช้เพื่อ audit/explainability) weight set จึงเปลี่ยน action ไม่ได้

ไม่มีการอ้างว่า "ลดเวลาตอบสนองได้ X%" เพราะไม่มี manual baseline ที่วัดได้อย่าง valid

---

## 5. Limitations

**L1 — Clock offset:** Clock offset between SEC01 and pfSense was not reduced to near-zero. During the
second experimental set, the measured offset changed from +183.87 ms at the beginning to +162.58 ms at
the end. The direction differed from the drift observed in the first set. No timestamp compensation was
applied. · วันที่ 2 ไม่ได้ resync (ไม่มีสิทธิ์ admin) · ชุด T2–T8 ไม่มีค่า offset ท้ายชุด · M1–M4 ใช้
นาฬิกา SEC01 ทั้งสองปลาย จึงไม่ได้รับผลจาก offset โดยตรง แต่ M1 รวมช่วง generate → inject ผ่าน SSH

**L2 — T9 event processing ระหว่าง CRITICAL:** The engine remained operational in the health loop after
entering CRITICAL, but event-processing continuity during CRITICAL was not directly verified because no
event was injected during this interval.

**L3 — T9 ไม่มี inter-attempt delay:** attempt 1–3 เกิดติดกันภายใน < 1 s (ไม่มี backoff)

**L4 — T9 failure message:** `failure_reason` มี stderr ของ SSH (post-quantum warning) ปนแทนข้อความของ
`/usr/bin/false` · rc=1 ทุก attempt ยังยืนยัน failure ได้

**L5 — Factor C = 30 (Known Lab Asset) ไม่ได้ทดลอง:** `config/assets.yaml` ว่างโดยตั้งใจ เพราะไม่มี
asset ใน lab ที่ยืนยัน role ได้ · dataset ครอบคลุมเฉพาะ C = 80 (unknown) และ C = 0 (allowlisted)

**L6 — T7 traffic verification:** ยืนยันได้ระดับ pf table read-back (engine + `pfctl -T show` @+10 s)
เท่านั้น · Layer 2 (ยิง traffic ผ่าน firewall) = NOT AVAILABLE เพราะ `198.51.100.77` เป็น TEST-NET
ไม่มี host จริง — ไม่ได้เติมผล

**L7 — Implementation revision:** T11 ใช้ `d0a346d` ต่างจาก T1–T10 (`236ce70`) · ก่อน T11 พบว่า
`risk.weight_set` จาก config ไม่ถูกส่งเข้า pipeline · T1–T10 ใช้ Set A ซึ่งตรงกับค่า default จึงไม่กระทบผล
แต่ไม่ได้รันด้วย revision เดียวกัน

**L8 — Controlled injection:** dataset หลักใช้ EVE injection ไม่ใช่ packet จริงผ่าน Suricata · M1 จึงเป็น
EVE ingestion latency · M3 แยก command กับ verification ไม่ได้ (`add_block()` ทำในครั้งเดียว)

**L9 — ขนาดตัวอย่าง:** 5 runs ต่อ test (T10 10, T11 3) · สถิติเป็นเชิงพรรณนา ไม่ใช่การอนุมาน
