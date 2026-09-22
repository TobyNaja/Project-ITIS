# Blueprint ↔ Repository Gap Matrix

> **Source of truth:** `Project ITIS.pdf` — *Master Project Blueprint & Implementation Guide*
> **Repository:** `feature/phase11-12 @ ff9ac58` · จัดทำ 2026-09-22
> เอกสารนี้เป็นผลการตรวจสอบ **ไม่ใช่ข้อเสนอการแก้ไข** — แผนแก้อยู่ใน `blueprint-alignment-plan.md`

สถานะที่ใช้: **E** = implemented + มี evidence · **I** = implemented แต่ไม่มี evidence ·
**N** = ยังไม่มี · **C** = conflict / design mismatch กับ blueprint

---

## 1. Test Cases T1–T11 (§14.4)

| T | Blueprint กำหนด | ของจริงใน repo | สถานะ |
|---|---|---|---|
| T1 Normal Traffic | ไม่มี alert → MONITOR, no block, system HEALTHY | ไม่มี scenario และไม่มีแนวคิด system health ในโค้ด | N |
| T2 Single Medium Alert | 1 MEDIUM alert → MONITOR (ห้าม block) | ไม่มี scenario; มีแค่ unit test correlation ที่ไม่ match | N |
| T3 Repeated Medium | 5 MEDIUM same src ≤10s → RULE-002 → ALERT | `A2` = 5 events **severity=3** → ALERT 30 trials | C |
| T4 Critical Pattern | 5 HIGH same src ≤10s not allowlisted → BLOCK → VERIFIED | `A3` = 5 events severity=1 → BLOCK verified 30 trials | E |
| T5 Allowlisted Critical | RULE-003 → NO_AUTO_BLOCK + ALERT + AUDIT, risk score ห้ามเป็น 0 | `A4` 30 trials NO_AUTO_BLOCK | E (ขาด AUDIT) |
| T6 Auto-Unblock | BLOCK → 300s → UNBLOCK → VERIFY → `EXPIRED` | lifecycle + runner + unit test ครบ; integration test skip; ไม่มี experiment | I |
| T7 Enforcement Verification | read-back **+ traffic verification** | read-back (`is_blocked`) มี; traffic verification ไม่มี | C |
| T8 Suricata Recovery | stop suricata → DEGRADED → restart → HEALTHY | ไม่มี health/recovery module | N |
| T9 Recovery Failure | fail ×3 → CRITICAL → stop retry (ห้ามมี attempt 4) | ไม่มี | N |
| T10 False Positive Sim | 1 HIGH **หรือ** 4 HIGH ≤10s → MONITOR, no block | `A1` = 4 events severity=1 → `decision=None` 30 trials (ตรงเคส 4 HIGH) | E (เคส 1 HIGH ยังไม่รัน) |
| T11 Sensitivity | Weight Set A/B/C, เก็บ 4 factor + final + level + decision | weights คงที่ในโค้ด, ไม่มี `test_sensitivity.py` | N |

**repetitions** — blueprint: T1–T10 × 5 (minimum) · repo: A1–A4 × 30
จำนวนรอบเกินเกณฑ์ แต่ครอบ test case ได้ **4 จาก 11**

### mapping ชื่อ scenario

`A1 → T10` · `A2 → T3` · `A3 → T4` · `A4 → T5`

ชื่อ A1–A4 **ไม่มีอยู่ใน blueprint** ต้องถือเป็น internal label เท่านั้น
และรายงานต้องใช้ T-number เป็น canonical ID

---

## 2. Metrics M1–M10 (§14.1)

| M | Blueprint นิยาม | ของจริง | สถานะ |
|---|---|---|---|
| M1 Detection Latency | `T_detection − T_event` (Suricata EVE → Python เห็น) | `detection_s = t0_received → t1_correlated` = correlation ในโปรเซส median 5.8 µs | C |
| M2 Decision Latency | `T_decision − T_detection`, target < 1s | `decision_s = t1_correlated → t3_decision` median 36 µs | E |
| M3 Enforcement Latency | `T_block_verified − T_decision`, **แยก** command / verification / total | `enforcement_s = t4_enforce_req → t5_enforce_ok` median 537 ms, ไม่แยก | E (บางส่วน) |
| M4 End-to-End | `T_block_verified − T_event` — metric หลักของ RQ | `end_to_end_s = t0_received → t5_enforce_ok` — **ไม่รวมเวลา Suricata** | C |
| M5 Detection Success Rate | detected / expected | ไม่มี — synthetic ป้อนเข้า pipeline ตรง ไม่ผ่าน Suricata | N |
| M6 Automated Action Success | verified actions / required | ข้อมูลมี (30/30 BLOCK verified) แต่ analyzer ไม่ได้ออกตัวเลข | I |
| M7 FPR under test scenarios | unnecessary blocks / non-block cases | ข้อมูลมี (A1+A2+A4 = 90 trials ไม่มี block หลุด) แต่ยังไม่มีนิยาม positive/negative | I |
| M8 Allowlist Safety Rate | allowlisted ไม่ถูก block / total | A4 30/30 | I |
| M9 Auto-Unblock Success | unblocked / expired | ไม่มี dataset — trace ไม่มี `t_unblock` | N |
| M10 Recovery Success Rate | recovered / injected failures | ไม่มี | N |

---

## 3. Objectives O1–O11 (§1.4)

| O | สถานะ | หลักฐาน / เหตุผล |
|---|---|---|
| O1 EVE ingestion | I | `eve_reader.py` มีอยู่ แต่ไม่มี test สักตัว และ Phase 12 ไม่ได้เดินผ่านมัน |
| O2 Correlation | E | `correlation/engine.py` + tests + traces |
| O3 Risk model | C | โครงสร้างครบ แต่ normalization ไม่ตรง §3.5 (ดูข้อ 5) |
| O4 Rule-based response | E | RULE-001/002/003 ผลลัพธ์ตรง blueprint |
| O5 pfSense temporary block | E | 30 BLOCK verified บน pfSense จริง |
| O6 Auto-unblock | I | โค้ด + unit test ครบ ไม่มี experiment |
| O7 Enforcement verification | E | read-back verified; ขาด traffic verification ตาม T7 |
| O8 Allowlist | E | `allowlist.py` + RULE-003 + A4 |
| O9 Audit trail | C | blueprint กำหนด 8 ตาราง — repo มีตารางเดียว (`active_blocks`) + JSONL trace |
| O10 Suricata recovery | N | ไม่มีไฟล์ใด ๆ |
| O11 Performance | I/N | latency ครบ; FPR / sensitivity / overhead ยังไม่มี |

---

## 4. Functional / Non-Functional Requirements

| ID | สถานะ | หมายเหตุ |
|---|---|---|
| FR-01 EVE tail + rotation | I | ไม่มี inode-aware rotation, ไม่มี test |
| FR-02 Normalize + filter | I | กรอง `alert` แล้ว แต่ไม่มีเส้นทาง `stats` → health |
| FR-03 Correlation | E | |
| FR-04 Risk + persist factor scores | C | คำนวณได้ แต่ไม่มีตาราง `risk_assessments` |
| FR-05 Rule priority | C | logic ถูก แต่ hardcode ไม่ได้มาจาก `rules.yaml` |
| FR-06 Allowlist override | C | logic ถูก แต่ไม่มี AUDIT record |
| FR-07 Block + action record | C | block ได้จริง แต่ไม่มีตาราง `actions` |
| FR-08 Verify enforcement | C | read-back มี, traffic test + `verify_result` ไม่มี |
| FR-09 Auto-unblock | I | โค้ด + test ครบ ไม่มี evidence จากการรันจริง |
| **FR-10 Restart resilience** | **PARTIAL** | `BlockLifecycleManager.reconcile()` มีและมี test 2 ชั้น แต่ **ไม่มี production caller** — พฤติกรรมเกิดขึ้นจริงโดยอ้อมผ่าน `LifecycleRunner` tick แรก |
| **FR-11 Duplicate handling** | **FAIL** | ดูข้อ 6 |
| FR-12 Health check | N | ไม่มี |
| FR-13 Recovery | N | ไม่มี |
| FR-14 Explainable decision | C | `reason` มีบางส่วนใน trace ไม่มีตาราง `decisions` |
| FR-15 Experiment timestamps | C | JSONL มี ไม่มีตาราง `experiment_timestamps` |
| NFR-01 Config-driven | C | ไม่มี `config.yaml` — ใช้ env + ค่าคงที่ใน Python |
| NFR-02 Error handling | I | external call บางจุดมี try/except ยังไม่ audit ครบ |
| NFR-03 Logging | N | ใช้ `print` ไม่มี `logs/engine.log` |
| NFR-04 UTC timestamps | I | ใช้ UTC แล้ว ยังไม่ audit ทุกจุด |
| NFR-05 SQLite safety | C | parameterized query ครบ แต่ไม่มี WAL, schema ไม่ตรง |
| NFR-06 Fail-safe direction | I | lifecycle จัดการ fail ได้ ยังไม่ต่อ ALERT/AUDIT |
| NFR-07 Credentials | E | env + `.gitignore` (commit `ae8e6ca`, `ff9ac58`) |
| NFR-08 Code style | I | ยังไม่ audit type hints ทั้ง repo |
| NFR-09 Testability | E | 152 passed / 10 skipped, DI ครบ |
| NFR-10 Decision < 1s | E | median 36 µs — ต้องวัดซ้ำหลัง freeze |

---

## 5. Risk Model — implementation drift จาก §3.5 (ล็อกแล้ว)

| Factor | Blueprint §3.5 | `security_engine/scoring/risk.py` | ผล |
|---|---|---|---|
| weights | .40 / .25 / .20 / .15 | ตรงทุกตัว | ตรง |
| S severity | sev3=25, sev2=50, sev1=75, custom=100 | `{0:100, 1:75, 2:50, 3:25}` | ตรง |
| F frequency | lookup 1=20, 2–3=40, **4–5=70**, >5=100 | `count/min_events×100` → **5 events = 100** | ต่าง |
| T temporal | lookup **≤10s=100**, ≤30s=75, ≤60s=50, >60s=25 | `(1 − window/window_max)×100` → **window=10s ได้ 0** | ต่าง |
| C context | Internal Known=30, Unknown/External=80, Allowlisted=0 | `factor_target_concentration` (สัดส่วน dest ยอดฮิต) | คนละแนวคิด |
| Weight Set B/C | กำหนดค่าไว้ครบ | ไม่มีในโค้ด | ไม่มี → T11 ทำไม่ได้ |

**ผลกระทบ:** ถ้าแก้ให้ตรง blueprint คะแนน risk ของทุก trial ใน Phase 12 จะเปลี่ยน
(dataset latency ไม่กระทบเพราะวัดเวลา ไม่ได้วัดคะแนน)

---

## 6. FR-11 Duplicate Handling — รายละเอียด (FAIL)

| ส่วนของ requirement | ผล | หลักฐาน |
|---|---|---|
| ไม่ block ซ้ำ | ไม่ผ่าน | `pipeline.py` เรียก `lifecycle.block()` ทุกครั้งที่ decision = BLOCK และ `block_lifecycle.py:51` เรียก `enforcer.add_block(ip)` โดยไม่เช็ค state |
| ไม่สร้าง timer ซ้อน | ผ่าน (โดยดีไซน์คนละแบบ) | ไม่มี per-IP timer — ใช้ `LifecycleRunner` poll ตัวเดียว |
| log duplicate pattern | ไม่ผ่าน | ไม่มี log ในเส้นทางนี้ |

**ผลข้างเคียงที่รุนแรงกว่า:** `block_store.py:70` ใช้ `INSERT OR REPLACE` กับ `src_ip` PRIMARY KEY
→ block ซ้ำไม่สร้างแถวซ้ำ แต่ **เขียนทับ `expires_at`** = เลื่อนเวลาหมดอายุเงียบ ๆ
ขัดกับ D5 (block duration เป็น experimental parameter) และทำให้ **M9 วัดผิดความหมาย**

`CorrelationEngine` มี cooldown = window (10s) จึงลด duplicate ได้บางส่วน
แต่ block duration = 300s → **เหลือช่องว่าง ~290 วินาที** ที่ duplicate เกิดได้จริง

---

## 7. CONFLICT ที่ต้องให้คนตัดสิน ไม่ใช่ให้โค้ดตัดสิน

1. **NFR-01** สั่ง `config.yaml` — commit `ff9ac58` ใช้ env + `config/allowlist.txt`
2. **severity vs risk level** — blueprint §3.4 ระบุ Suricata `1=High, 2=Medium, 3=Low`
   แต่ `A2` ใช้ `severity=3` แล้วได้ผลลัพธ์ *risk level* = MEDIUM
   → ห้ามเขียนในรายงานว่า "5 Medium alerts"
3. **M1 / M4 boundary** — `t0_received ≠ T_event` ตราบใดที่เป็น synthetic
   → M1/M4 ตามนิยาม blueprint **วัดไม่ได้จนกว่าจะมี Mode C**
4. **`allowlist.yaml` vs `allowlist.txt`** และ `rules.yaml` vs rules ที่ hardcode ใน Python
5. **Prometheus / Grafana** อยู่ใน scope ของ blueprint แต่ยังไม่มีในระบบ

---

## 8. สถานะ dataset Phase 12

Phase 12 เป็น **pre-freeze evidence** — ผลจาก implementation ก่อน blueprint alignment
latency (detection / decision / enforcement / end-to-end) ยังมีคุณค่าในฐานะ engineering measurement
แต่ **ห้ามนำคะแนน risk จาก dataset นี้ไปปนกับผลหลังแก้ Risk Model**
