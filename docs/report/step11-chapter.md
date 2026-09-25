# บทที่ — ผลการทดลอง การอภิปรายผล และสรุป (STEP 11 / Blueprint Phase 14–15)

> ร่างสำหรับรายงานฉบับจริง · แหล่งข้อมูลทั้งหมดมาจาก dataset ที่ freeze แล้ว (commit `8d31ae7`):
> `data/step11_experiment.db` (SHA-256 `d4ffe244…9b805`), `docs/evidence/step11_runs.csv`,
> `experiments/results_step11.csv`, `docs/evidence/step11_metrics.md` · ตารางย่อ/รายละเอียดเพิ่มอยู่ใน
> `docs/step11_results.md` · ไม่มีการ rerun หรือแก้ dataset หลัง freeze

---

## 1. การดำเนินการทดลอง (Experimental Execution)

**สภาพแวดล้อม:** pfSense 2.7.2 + Suricata 7.0.8 บน GNS3 (เครื่อง IDS/firewall) · engine (Python) รันบน
Windows host (SEC01) อ่าน EVE JSON ผ่าน SSH · SQLite เป็น audit trail · block ผ่าน pf table `ITIS_BLOCK_TEST`

**Input หลัก:** controlled EVE injection — `scripts/generate_test_events.py` สร้าง EVE alert แล้วต่อท้าย
`eve.json` บน pfSense ผ่าน SSH · `t_event` ถูกสร้างบนนาฬิกา SEC01 เดียวกับ timestamp อื่นทั้งหมด
(same-host measurement) · T1 ไม่ inject (สังเกต traffic ปกติ) · T8/T9 เป็น fault injection
(`suricata.sh stop`)

**จำนวน run:** 58 runs — T1–T9 อย่างละ 5 · T10 10 (variant a 5 + variant b 5) · T11 3 (Weight Set A/B/C)
· engine เริ่มใหม่ทุก run (1 process = 1 run) · DRYRUN (`T4-R00`) แยกไว้นอก dataset

**ช่วงเวลา:** ชุดที่ 1 — 2026-09-24 (T1–T8) · ชุดที่ 2 — 2026-09-25 (T9–T11)

**Code revision:** T1–T10 ใช้ `236ce70` · T11 ใช้ `d0a346d` — ก่อน T11 พบว่า `risk.weight_set` ที่ตั้งใน config
ถูกบันทึกลง log แต่ไม่ถูกส่งเข้า pipeline (ทุก run คำนวณด้วย Set A) จึงแก้และเพิ่ม test ก่อนรัน T11 ·
T1–T10 ตั้ง Set A ซึ่งเท่ากับค่า default ผลจึงไม่เปลี่ยน แต่ไม่ได้รันด้วย revision เดียวกัน (L7)

**การตรวจความครบถ้วนของ dataset:** 58/58 runs ครบตาม mapping · run_id ไม่ซ้ำ · ช่วงเวลา engine ไม่ซ้อนกัน ·
ทุกแถวในฐานข้อมูลผูกกับ run ได้ · `PRAGMA integrity_check = ok` · ไม่มี block ค้าง (`docs/evidence/step11_validation.md`)

---

## 2. ผลการทดสอบเชิงฟังก์ชัน (T1–T11)

**ตารางที่ 1** ผลการทดสอบ T1–T11

| Test | Scenario | Expected | Actual | Runs | Outcome |
|---|---|---|---|---|---|
| T1 | Normal traffic | MONITOR / no block | ไม่มีแถวใหม่ใน audit trail · pf table ว่าง | 5 | 5/5 PASS |
| T2 | 1 × MEDIUM | MONITOR / no block | บันทึก event 1 แถว · ไม่ถึงเงื่อนไข correlation | 5 | 5/5 PASS |
| T3 | 5 × MEDIUM / 10 s | ALERT (RULE-002) | RULE-002 ALERT · risk 69.5 HIGH · ไม่มี block | 5 | 5/5 PASS |
| T4 | 5 × HIGH / 10 s | BLOCK → VERIFIED (RULE-001) | RULE-001 BLOCK · risk 79.5 HIGH · SUCCESS + VERIFIED | 5 | 5/5 PASS |
| T5 | 5 × HIGH จาก allowlisted source | NO_AUTO_BLOCK (RULE-003) | RULE-003 · C = 0 · risk 67.5 · ไม่มี block | 5 | 5/5 PASS |
| T6 | Block expiry | UNBLOCK หลัง 300 s | UNBLOCK VERIFIED ที่ 300.4–301.3 s | 5 | 5/5 PASS |
| T7 | Enforcement verification | VERIFIED | engine read-back VERIFIED + `pfctl` read-back พบ IP ใน table | 5 | 5/5 PASS (read-back) |
| T8 | Suricata หยุด | DEGRADED → restart → HEALTHY | กู้คืนสำเร็จที่ attempt 1 · PID ใหม่ · stats กลับมา | 5 | 5/5 PASS |
| T9 | Suricata หยุด + restart ใช้ไม่ได้ | 3 attempts → CRITICAL | FAIL → FAIL → CRITICAL · ไม่มี attempt 4 | 5 | 5/5 PASS |
| T10a | 1 × HIGH | MONITOR / no block | ไม่มี decision/action | 5 | 5/5 PASS |
| T10b | 4 × HIGH / 10 s | MONITOR / no block | 4 < min_events (5) · ไม่มี decision/action | 5 | 5/5 PASS |
| T11 | 5 × HIGH, Set A/B/C | risk เปลี่ยนตาม weight set | ดูหัวข้อ 4 | 3 | บันทึกครบ 3/3 |

T1–T10: 55/55 runs ได้ผลตาม expected · T11 เป็น sensitivity analysis ไม่ตัดสิน pass/fail

หมายเหตุ: ระหว่าง T4-R03, T7-R03 และ T11-R01 มี alert จริงจาก network (IPv6 link-local → ff02::2,
sid 1000001) ถูกบันทึกอย่างละ 1 แถว — ไม่ใช่ input ของ test และไม่ถูกนับในผล

---

## 3. ผลการวัดประสิทธิภาพ (M1–M10)

**ตารางที่ 2** Latency (ms) — จาก `experiment_timestamps`, นาฬิกา SEC01 ทั้งสองปลาย

| Metric | นิยาม | กลุ่ม | n | Mean | Median | Min–Max | SD |
|---|---|---|---|---|---|---|---|
| M1 Detection (EVE ingestion) | t_detection − t_event | T3+T4 | 10 | 910.4 | 903.3 | 833.2–966.3 | 43.5 |
| M2 Decision | t_decision − t_detection | T3+T4 | 10 | 69.2 | 60.4 | 57.2–118.1 | 20.8 |
| M3 Enforcement (รวม) | t_block_verified − t_decision | T4+T7 | 10 | 643.1 | 617.8 | 526.9–971.7 | 126.0 |
| └ ก่อนเรียก block | t_block_cmd − t_decision | T4+T7 | 10 | 231.2 | 225.0 | 171.9–306.4 | 45.3 |
| └ command + verification | t_block_verified − t_block_cmd | T4+T7 | 10 | 411.9 | 382.7 | 325.4–733.7 | 116.1 |
| M4 End-to-End | t_block_verified − t_event | T4 | 5 | 1593.4 | 1584.1 | 1513.4–1695.5 | 74.0 |

M3 ส่วน `t_block_verified − t_block_cmd` เป็นเวลารวม command + verification เนื่องจาก implementation
ปัจจุบันสั่ง block และตรวจผลในการเรียกครั้งเดียว จึง timestamp สองขั้นตอนนี้แยกกันไม่ได้ —
ค่านี้ **ไม่ใช่** pure command latency

**ตารางที่ 3** Success / safety metrics

| Metric | ขอบเขต | Result | นิยาม |
|---|---|---|---|
| M5 Detection Success | T1–T4 | 55/55 (100%) | alert ที่ inject ถูกบันทึก / alert ที่ inject |
| M6 Automated Action Success | T4, T7 | 10/10 (100%) | BLOCK SUCCESS + VERIFIED / decision BLOCK |
| M7 False Positive (scenario-defined) | T1, T2, T3, T10 | 0/25 (0%) | block ที่ไม่ควรเกิด / non-block cases |
| M8 Allowlist Safety | T5 | 5/5 (100%) | allowlisted source ที่ไม่ถูก block |
| M9 Auto-Unblock Success | T6 | 5/5 (100%) | UNBLOCK VERIFIED / block ที่หมดอายุ |
| M10 Recovery Success | T8 | 5/5 (100%) | กู้คืนสำเร็จ / failure ที่ออกแบบให้กู้ได้ · mean 26,357 ms |
| T9 Recovery Failure Handling | T9 | 5/5 | หยุดที่ 3 attempts → CRITICAL ไม่มี attempt 4 |
| M10 aggregate (supplementary) | T8+T9 | 5/10 | รวม T9 ที่ออกแบบให้กู้ไม่ได้ — ไม่ใช่ตัวแทนความสามารถ recover |

M7 เป็นอัตราภายใต้ scenario ที่กำหนดเท่านั้น ไม่ใช่ false positive rate ของระบบโดยทั่วไป

**รูปที่ 1** องค์ประกอบของ M4 ต่อ run (ทุก run ที่ block, n = 18)

![M4 breakdown](figures/step11_m4_breakdown.png)

---

## 4. Sensitivity Analysis (T11)

**ตารางที่ 4** ผลของ weight set ต่อ pattern เดียวกัน (5 × HIGH ภายใน 10 s, source ภายนอก)

| Weight set | S | F | T | C | Risk score | Risk level | Rule | Decision | Enforcement |
|---|---|---|---|---|---|---|---|---|---|
| A | 75 | 70 | 100 | 80 | 79.5 | HIGH | RULE-001 | BLOCK | VERIFIED |
| B | 75 | 70 | 100 | 80 | 80.5 | CRITICAL | RULE-001 | BLOCK | VERIFIED |
| C | 75 | 70 | 100 | 80 | 78.5 | HIGH | RULE-001 | BLOCK | VERIFIED |

Under the tested input pattern, changing the weight set changed the numerical risk score and risk
classification, but did not change the resulting rule-based action; all three sets resulted in RULE-001
BLOCK with successful verification.

---

## 5. การบรรลุวัตถุประสงค์ (O1–O11)

**ตารางที่ 5** สถานะวัตถุประสงค์จากผลการทดลองจริง

| Objective | สถานะ | หลักฐาน |
|---|---|---|
| O1 รับ Security Event จาก Suricata (EVE JSON) | PASS | alert ที่ inject ถูกบันทึกครบ 170/170 (M5) |
| O2 Event Correlation | PASS | pattern ถึงเกณฑ์ (T3/T4) ถูก correlate · ต่ำกว่าเกณฑ์ (T2, T10) ไม่ถูก correlate |
| O3 Risk Assessment Model | PASS | S/F/T/C และ risk score ตรงกับ golden case (79.5, Set A) · Set B/C ให้ค่าต่างกันตามน้ำหนัก (T11) |
| O4 Rule-Based Automated Response | PASS | RULE-001/002/003 ให้ผลตามที่กำหนดทุก run (T3, T4, T5) |
| O5 pfSense Temporary Block | PASS | BLOCK SUCCESS + VERIFIED 18/18 |
| O6 Auto-Unblock | PASS | T6 5/5 · ทุก block ใน dataset unblock สำเร็จ 18/18 |
| O7 Verify การ enforce จริง | PASS (ระดับ read-back) | engine read-back + `pfctl` read-back 5/5 · traffic verification ทำไม่ได้ (L6) |
| O8 Allowlist Safety | PASS | T5 5/5 ไม่ถูก block |
| O9 Audit Trail | PASS | 8 ตารางมีข้อมูลเชื่อมโยงกันครบ (event → pattern → risk → decision → action) |
| O10 Functional Recovery (retry ≤ 3) | PASS | T8 กู้คืน 5/5 · T9 หยุดที่ 3 attempts 5/5 |
| O11 Performance | PARTIAL | latency, scenario-defined FP, sensitivity วัดได้ · **overhead (CPU/RAM/PPS) ไม่ได้วัด** (L10) |

---

## 6. อภิปรายผล (Discussion)

**6.1 ผลนี้หมายความว่าอะไร** — ภายใต้เงื่อนไขที่กำหนด สายการทำงานอัตโนมัติ event → correlation → risk →
rule → block → verify → unblock ทำงานครบทุก run ที่ออกแบบให้ block (18/18) และไม่เกิด block ในทุก run ที่ออกแบบ
ให้ไม่ block (25/25 + allowlisted 5/5) ผลลัพธ์จึงเป็นไปตาม rule ที่กำหนดไว้ล่วงหน้าอย่างสม่ำเสมอ
(deterministic) ในทุก run ที่ทดสอบ

**6.2 ทำไม M4 จึงประมาณ 1.59 s** — จากรูปที่ 1 และค่าเฉลี่ยของ T4: EVE ingestion (M1) 930.7 ms ≈ 58% ·
decision (M2) 66.9 ms ≈ 4% · ช่วงก่อนเรียก block 206.9 ms ≈ 13% · command + verification 388.8 ms ≈ 24%
(ทุก run ที่ block n = 18 ให้สัดส่วนใกล้เคียงกัน: 57 / 4 / 14 / 24%) · เวลาส่วนใหญ่จึงอยู่ที่การส่ง event
เข้า engine และการสื่อสารกับ pfSense ผ่าน SSH ไม่ใช่ตรรกะ correlation/decision · M1 รวมช่วง
generate → ส่ง event ผ่าน SSH → ต่อท้าย eve.json → อ่านกลับผ่าน SSH tail จึงสะท้อนกลไก ingestion
ของ lab นี้ ไม่ใช่เวลาที่ Suricata ใช้ตรวจจับ packet

**6.3 Correlation/decision เทียบกับ enforcement + verification** — ตรรกะภายใน engine (M2 ~69 ms) ใช้เวลาเพียง
ประมาณ 1 ใน 9 ของ M3 (~643 ms) · ช่วงก่อนเรียก block (~231 ms) รวมการบันทึก decision ลงฐานข้อมูลก่อนสั่ง
enforcement · ความแปรปรวนที่มากที่สุดอยู่ใน command + verification (SD 116 ms, สูงสุด 733.7 ms ใน T7-R04)
ซึ่งสอดคล้องกับการที่ขั้นนี้ขึ้นกับ SSH round-trip และภาระของ pfSense

**6.4 ผลของ allowlist** — allowlist มีผลสองชั้นตามที่ออกแบบ: ในชั้น Risk ลด factor C เป็น 0 (risk 67.5
แทน 79.5 — ยังเป็น HIGH ไม่ได้ทำให้ score เป็นศูนย์) และในชั้น Rule ทำให้ RULE-003 NO_AUTO_BLOCK
มีผลเหนือ RULE-001 · T5 จึงแสดงว่าการป้องกัน block ไม่ได้พึ่งการลดคะแนนเพียงอย่างเดียว แต่เป็น
enforcement override โดยตรง

**6.5 Recovery behaviour เทียบกับ design** — T8: health check ตรวจพบ PROCESS_DOWN ภายในรอบตรวจถัดไป
(check interval 15 s) แล้วกู้คืนสำเร็จที่ attempt แรกทุก run รวม ~26.4 s ตั้งแต่สั่งหยุดจนได้ stats ใหม่ ·
T9: เมื่อ restart ใช้ไม่ได้ ระบบหยุดที่ 3 attempts และคงสถานะ CRITICAL (ไม่ retry ต่อ) ตรงกับข้อกำหนด
retry ≤ 3 · อย่างไรก็ตาม attempt ทั้งสามเกิดติดกันภายใน < 1 s จึงไม่ได้เว้นระยะให้ปัญหาชั่วคราวหายเอง (L3)

**6.6 Sensitivity ของ weight** — weight set เปลี่ยน risk score ได้ ±1 คะแนนและทำให้ Set B ข้ามเกณฑ์
CRITICAL (≥ 80) แต่ action ไม่เปลี่ยน · สาเหตุเป็นเชิงโครงสร้าง ไม่ใช่เพราะคะแนนบังเอิญอยู่ในช่วงเดียวกัน:
ตาม design (§3.5, `config/rules.yaml`) เงื่อนไขของ rule ใช้ severity ของ alert, จำนวน event ต่อ source,
time window และ allowlist — **ไม่ใช้ risk_level/risk_score** ซึ่งเก็บไว้เพื่อ audit/explainability เท่านั้น ·
ดังนั้นใน implementation นี้ weight set มีผลต่อคะแนนและการจัดระดับที่แสดงใน audit trail แต่ไม่มีเส้นทาง
ที่จะเปลี่ยน action ได้ ไม่ว่า pattern ใด · T11 ยืนยันพฤติกรรมนี้เชิงประจักษ์ และไม่ได้บอกว่า set ใดเหมาะสมกว่า

**6.7 ทำไม generalize ไป production ไม่ได้** — input เป็น controlled injection จาก source เดียว
(TEST-NET) บน lab ที่มี traffic น้อย · ไม่ได้ทดสอบ traffic จริงปริมาณมาก, หลาย source พร้อมกัน,
หรือ attack ที่ Suricata rule ไม่ครอบคลุม · ไม่ได้วัด overhead · ขนาดตัวอย่าง 5 runs ต่อ test

---

## 7. ข้อค้นพบ (Findings)

- **F1** ภายใต้ controlled network environment และ predefined rules ระบบสามารถ correlate IDS events
  แล้วนำไปสู่ predefined firewall response พร้อม verification และ lifecycle management ได้ครบทุก run
  ที่คาดให้ block (M6 10/10, M9 5/5) และวัด end-to-end ได้จริง (M4 mean 1593.4 ms)
- **F2** เวลาส่วนใหญ่ของ automated path อยู่ที่ EVE ingestion (~58%) และ command + verification (~24%)
  · correlation/decision ภายใน engine ใช้ ~4%
- **F3** ภายใต้ scenario ที่ทดสอบ ไม่มี block ที่ไม่ควรเกิด (M7 0/25) และ allowlisted source ไม่ถูก block (M8 5/5)
- **F4** ระบบกู้คืน Suricata ได้เมื่อ restart ทำได้ (M10 5/5) และหยุด retry ที่ 3 ครั้งเมื่อกู้ไม่ได้ (T9 5/5)
- **F5** weight set มีผลต่อ risk score/classification แต่ไม่เปลี่ยน action ใน pattern ที่ทดสอบ
  ซึ่งสอดคล้องกับ design ที่เงื่อนไขของ rule ไม่อิง risk level (§3.5) — risk score ทำหน้าที่อธิบาย
  การตัดสินใจ (explainability) ไม่ใช่ตัวกำหนด action

---

## 8. ข้อจำกัด (Limitations)

### 8.1 ข้อจำกัดตาม Blueprint §15.3

**Risk Model** — The proposed risk scoring model is a rule-based weighted model developed for the
controlled experimental environment. The weights and normalization mappings are experimental design
parameters and are not claimed to represent a universal industry standard.
(แนวคิด informed by established cybersecurity assessment concepts เช่น CVSS v4.0 สำหรับ severity และ
NIST Incident Handling สำหรับ incident response — ไม่ใช่คะแนนมาตรฐานสากลโดยตรง)

**Detection** — Detection capability depends on the configured Suricata rules and therefore does not
represent detection of all possible attack types.

**Automated Blocking** — Automated blocking may introduce operational risks, particularly in the presence
of false positives. The allowlist and verification mechanisms were therefore included as safety controls.

**Experimental Environment** — The evaluation was conducted in a controlled laboratory environment and
should not be interpreted as production-level performance.

**Recovery** — The recovery mechanism focuses on functional health of Suricata and does not constitute
complete service orchestration or high-availability architecture.

### 8.2 ข้อจำกัดที่พบจากการทดลองนี้

- **L1 Clock offset** — Clock offset between SEC01 and pfSense was not reduced to near-zero. During the
  second experimental set, the measured offset changed from +183.87 ms at the beginning to +162.58 ms at
  the end. The direction differed from the drift observed in the first set. No timestamp compensation was
  applied. (ชุดที่ 2 ไม่ได้ resync เพราะไม่มีสิทธิ์ admin · ชุด T2–T8 ไม่มีค่า offset ท้ายชุด · M1–M4
  ใช้นาฬิกา SEC01 ทั้งสองปลาย จึงไม่ได้รับผลจาก offset นี้โดยตรง)
- **L2 T9 event processing** — The engine remained operational in the health loop after entering CRITICAL,
  but event-processing continuity during CRITICAL was not directly verified because no event was injected
  during this interval.
- **L3 T9 retry timing** — attempt 1–3 เกิดติดกันภายใน < 1 s ไม่มี inter-attempt delay
- **L4 T9 failure message** — `failure_reason` มีข้อความเตือนของ SSH ปนแทนข้อความของ `/usr/bin/false`
  · rc=1 ทุก attempt ยังยืนยัน failure ได้
- **L5 Factor C = 30** — Known Lab Asset ไม่ได้ทดลอง เพราะไม่มี asset ใน lab ที่ยืนยัน role ได้
  (`config/assets.yaml` ว่างโดยตั้งใจ) · dataset ครอบคลุม C = 80 และ C = 0 เท่านั้น
- **L6 T7 traffic verification** — ยืนยันได้ระดับ pf table read-back เท่านั้น · การยิง traffic ผ่าน firewall
  = NOT AVAILABLE เพราะ source เป็น TEST-NET ไม่มี host จริง (ไม่ได้เติมผล)
- **L7 Implementation revision** — T11 ใช้ `d0a346d` ต่างจาก T1–T10 (`236ce70`)
- **L8 Controlled injection** — dataset หลักไม่ใช่ packet จริงผ่าน Suricata · M1 = EVE ingestion latency
  · M3 แยก command กับ verification ไม่ได้
- **L9 ขนาดตัวอย่าง** — 5 runs ต่อ test (T10 10, T11 3) · สถิติเชิงพรรณนาเท่านั้น
- **L10 Overhead ไม่ได้วัด** — ไม่มีข้อมูล CPU/RAM/PPS ระหว่างการทดลอง (Prometheus/Grafana ไม่ได้ติดตั้ง)
  · O11 จึงบรรลุบางส่วน

---

## 9. สรุป (Conclusion)

**Research Question:** *Can rule-based correlation of IDS events reduce the time required to enforce a
predefined firewall response in a controlled network environment?*

ภายใต้เงื่อนไขการทดลองที่กำหนด — lab ควบคุม, controlled EVE injection, predefined rules และ
Weight Set A — การ correlate IDS events แบบ rule-based ทำให้ firewall response ที่กำหนดไว้ล่วงหน้าถูก
enforce และยืนยันผลบน pfSense ได้โดยอัตโนมัติ ด้วย end-to-end time เฉลี่ย 1593.4 ms (T4, n = 5,
ช่วง 1513.4–1695.5 ms) นับจากเวลาที่ event ถูกสร้างจนถึงเวลาที่ยืนยันว่า block มีผลใน pf table
พร้อมกลไกความปลอดภัย (ไม่ block เมื่อไม่ถึงเกณฑ์, allowlist override) และ lifecycle (unblock
อัตโนมัติหลัง 300 s) ที่ทำงานได้ครบทุก run ที่ทดสอบ

การทดลองนี้ **ไม่ได้** วัด manual-response baseline (Blueprint §1.5 กำหนดให้ใช้ End-to-End Latency แทน
การเปรียบเทียบ manual vs automated) จึงสิ่งที่พิสูจน์ได้คือเวลาของ automated path และความสำเร็จของ
predefined response ภายใต้ scenario ที่กำหนด — ไม่ใช่เปอร์เซ็นต์ที่เวลาลดลงเมื่อเทียบกับการทำงานด้วยมือ
และไม่ควรนำไป extrapolate เป็นประสิทธิภาพใน production

---

## 10. งานในอนาคต (Future Work)

- เพิ่ม inter-attempt delay/backoff ใน recovery และทดสอบการประมวลผล event ระหว่าง CRITICAL (L2, L3)
- แยก timestamp ของ command กับ verification ใน enforcement path (L8)
- ทดสอบ traffic verification ด้วย host จริงหลัง firewall (L6) และ factor C = 30 เมื่อมี asset ที่ยืนยันได้ (L5)
- วัด overhead ด้วย Prometheus/Grafana (L10) และแก้การเก็บ stderr ของ SSH ใน failure_reason (L4)
- Adaptive blocking (escalating duration) ซึ่งอยู่นอก scope ของโครงงานนี้
