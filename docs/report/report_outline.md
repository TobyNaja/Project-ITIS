# Report Outline — Project ITIS

**ชื่อโครงงาน (ตามที่ยื่น — ห้ามเปลี่ยน, Blueprint หน้าแรก):** Security Event Correlation + Risk-Based Automated
Response + Security Service Recovery (ระบบวิเคราะห์เหตุการณ์ด้านความปลอดภัยและตอบสนองต่อภัยคุกคามแบบอัตโนมัติ
โดยใช้การประเมินความเสี่ยงและการกู้คืนบริการด้านความปลอดภัย)

**ขั้นตอน:** outline นี้ → เขียนบท 1 → 7 ทีละบท (Markdown) → consistency check ทั้งเล่ม (§ D) → DOCX/PDF
· ไม่มีการแก้ code/dataset ระหว่างเขียน

---

## A. Source of truth ต่อบท

| บท | เนื้อหา | Source of truth | ห้ามใช้เป็นแหล่ง |
|---|---|---|---|
| 1 บทนำ | ที่มา, problem, RQ, O1–O11, scope, ประโยชน์ | Blueprint §1.1–1.6, §2 | — |
| 2 ทฤษฎี | pfSense/pf, Suricata/EVE, correlation, risk assessment, rule-based response, allowlist, CVSS/NIST (แนวคิด) | แหล่งอ้างอิงภายนอก + Blueprint §1.6 (ข้อความ disclaimer) | ความเข้าใจทั่วไปที่ไม่มีอ้างอิง |
| 3 ออกแบบ | architecture, data flow, sequence, risk model, rules, schema, recovery, fail-safe | **code + config ปัจจุบัน** (`security_engine/`, `config/*.yaml`, `storage/schema.py`) ตรวจเทียบ Blueprint §3 | `docs/blueprint-gap-matrix.md`, `docs/report/phase12-results.md` (สถานะก่อน alignment) |
| 4 พัฒนา | implementation ต่อ component, configuration, testing | code + tests (828 passed / 10 skipped) · `docs/test_plan.md` | — |
| 5 ทดลอง | environment, topology, protocol, T1–T11, M1–M10, timestamp method, dataset freeze | `docs/test_plan.md` · `docs/evidence/step11_*.md` · `step11_runs.csv` | — |
| 6 ผลและอภิปราย | ผล T1–T11, M1–M10, T11, discussion, limitations | `docs/report/step11-chapter.md` (เรียบเรียงใหม่ ไม่ copy) · ตัวเลขทุกตัวต้องตรง `docs/evidence/step11_metrics.md` | คำนวณใหม่ |
| 7 สรุป | ตอบ RQ, สรุป, limitations, future work | บท 6 + Blueprint §15.3 | — |

---

## B. โครงสร้างเล่ม (ตามฉบับที่เขียนจริง — อัปเดต 2026-09-26 หลัง consistency check)

**Front matter (เพิ่มตอนรวมเล่ม ไม่อยู่ในบท 1–7):** ปก (ชื่อโครงงานตามที่ยื่น) · บทคัดย่อ (ไทย/อังกฤษ) · กิตติกรรมประกาศ · สารบัญ/สารบัญตาราง/สารบัญรูป

| บท | ไฟล์ | หัวข้อหลัก |
|---|---|---|
| 1 บทนำ | `chapter1-introduction.md` | 1.1 ที่มา · 1.2 problem statement · 1.3 RQ · 1.4 O1–O11 (ตาราง 1.1) · 1.5 ขอบเขต · 1.6 ประโยชน์ · 1.7 ข้อจำกัด · 1.8 โครงสร้างรายงาน |
| 2 ทฤษฎี | `chapter2-theory.md` | 2.1–2.10 แนวคิด (pfSense/pf, Suricata/EVE, correlation, CVSS/NIST, IRS, allowlist/fail-safe, recovery, SOAR) · 2.11 งานที่เกี่ยวข้อง · 2.12 สรุป · อ้างอิง |
| 3 ออกแบบ | `chapter3-design.md` | 3.1 architecture · 3.2 network · 3.3 Suricata · 3.4 EVE processing · 3.5 correlation · 3.6 risk (ตาราง 3.2–3.4) · 3.7 rules + allowlist (ตาราง 3.5) · 3.8 blocking/verification · 3.9 unblock/recovery · 3.10 data flow/DB (ตาราง 3.7) · 3.11 modules/parameters · 3.12 การออกแบบการทดลอง — fail-safe อยู่ใน 3.8–3.9 ไม่แยกหัวข้อ |
| 4 พัฒนา | `chapter4-implementation.md` | 4.1 เครื่องมือ · 4.2 configuration · 4.3 ingestion · 4.4 pipeline · 4.5 correlation · 4.6 risk · 4.7 rule · 4.8 enforcer · 4.9 lifecycle · 4.10 audit · 4.11 health/recovery · 4.12 logging · 4.13 instrumentation · 4.14 testing |
| 5 ทดลอง | `chapter5-experiment.md` | 5.1 environment · 5.2 การเตรียมระบบ (dry run) · 5.3 วิธีการ (injection, ขั้นตอน, จำนวนรอบ, revision) · 5.4 T1–T11 · 5.5 timestamp · 5.6 M1–M10 + M11–M14 · 5.7 วิธีวิเคราะห์ · 5.8 dataset control/freeze · 5.9 สรุป — **ไม่มีตัวเลขผล** |
| 6 ผล/อภิปราย | `chapter6-results.md` | 6.1 T1–T11 · 6.2 M1–M4 + รูป 6.1 · 6.3 M5–M10, T9, recovery time (supplementary) · 6.4 T11 · 6.5 O1–O11 · 6.6 อภิปราย · 6.7 F1–F5 · 6.8 ข้อจำกัด + deviations — **ไม่มี RQ/conclusion/future work** |
| 7 สรุป | `chapter7-conclusion.md` | 7.1 สรุปการดำเนินงาน · 7.2 ตอบ RQ · 7.3 ผลตามวัตถุประสงค์ · 7.4 ข้อจำกัด · 7.5 แนวทางพัฒนาต่อ |
| ภาคผนวก | `appendix.md` | ก frozen dataset + SHA-256 เต็ม + การแก้เอกสารหลัง freeze · ข registry 58 runs · ค commit/revision |

**ไม่รวมในเล่ม:** `phase12-results.md` (สถานะก่อน alignment) · `step11-chapter.md` (ร่าง ใช้เป็นวัตถุดิบบท 6)

---

## C. ข้อเท็จจริงที่ต้องใช้ตรงกันทั้งเล่ม (ตรวจกับ code 2026-09-25)

**Risk model** (`security_engine/scoring/risk.py`): R = S·w_S + F·w_F + T·w_T + C·w_C, ทุก factor 0–100

| Weight set | S | F | T | C |
|---|---|---|---|---|
| A (default) | 0.40 | 0.25 | 0.20 | 0.15 |
| B | 0.30 | 0.30 | 0.25 | 0.15 |
| C | 0.50 | 0.20 | 0.15 | 0.15 |

- S: Suricata severity 1 → 75 · 2 → 50 · 3 → 25 · 0 (custom critical ของโปรเจกต์) → 100 · นอกตาราง → 25
- F (lookup): 1 event → 20 · 2–3 → 40 · 4–5 → 70 · > 5 → 100
- T (lookup, absolute): ≤ 10 s → 100 · ≤ 30 s → 75 · ≤ 60 s → 50 · > 60 s → 25
- C (**source context**): allowlisted → 0 · known lab asset → 30 · unknown/external → 80
- Level: 0–29 LOW · 30–59 MEDIUM · 60–79 HIGH · 80–100 CRITICAL — **ใช้เพื่อ audit/report ไม่ใช่ตัวตัดสิน**

**Rules** (`config/rules.yaml`, priority น้อยประเมินก่อน, first match wins)

| Priority | Rule | Condition | Action |
|---|---|---|---|
| 1 | RULE-003 | source อยู่ใน allowlist | NO_AUTO_BLOCK (+ ALERT + audit) |
| 2 | RULE-001 | severity ≥ HIGH, ≥ 5 events same src, ≤ 10 s, ไม่อยู่ใน allowlist | BLOCK 300 s |
| 3 | RULE-002 | severity ≥ MEDIUM, ≥ 5 events same src, ≤ 10 s | ALERT |
| — | default | pattern ไม่ match rule ใด | MONITOR |

- ไม่มี rule ใดใช้ risk_level/risk_score เป็นเงื่อนไข · pattern ต่ำกว่า min_events ไม่ถูกสร้าง → ไม่มีแถว decision

**Parameters:** correlation window 10 s · min_events 5 · block 300 s · health check 15 s · stats freshness 30 s
· restart wait 5 s · max recovery attempts 3

**สิ่งที่อยู่ใน Blueprint แต่ไม่ได้ implement — ต้องเขียนตามจริง:**
- **Prometheus + Grafana** (Blueprint §1.1 ข้อ 10, Phase 13, Grafana 10 panels = Should-Have) — ไม่ได้ติดตั้ง
  → บท 3 แสดงเป็น monitoring layer ตาม design ที่ **ไม่ได้ implement** · บท 6/7 ระบุเป็นข้อจำกัด (overhead ไม่ได้วัด, O11 PARTIAL)
- Kali traffic — ไม่ใช่ input ของ dataset หลัก
- Traffic-path verification (T7 Layer 2) — NOT AVAILABLE

---

## D. ถ้อยคำที่ล็อก (ใช้ทั้งเล่ม)

| ห้ามเขียน | ให้เขียน |
|---|---|
| Risk score determines whether the IP is blocked. | Risk assessment provides a weighted assessment of the correlated pattern, while the Rule Engine determines the response action according to predefined conditions. |
| The system detects false positives at 0% / FPR = 0% | No unnecessary block was observed in the predefined non-block scenarios used in this experiment (M7: 0/25). |
| Firewall enforcement was fully verified. | Firewall state enforcement was verified through engine and pfctl read-back; direct traffic-path verification was not available in the experimental environment. |
| The system reduces response time (by X%). | The experiment measured the latency of the automated response path, with an observed mean end-to-end latency of 1,593.4 ms for T4. |
| M3 = command latency | M3 = enforcement latency; `t_block_verified − t_block_cmd` = command + verification combined |
| Weight set X is best / weight affects action | Weights changed the risk score/classification but not the action, because rule conditions do not use risk level. |
| Risk score เป็นมาตรฐานสากล | rule-based weighted model developed for the controlled experimental environment, informed by CVSS v4.0 / NIST incident handling concepts |
| วัด overhead แล้ว | overhead (CPU/RAM/PPS) ไม่ได้วัด |
| production-ready / generalizable | ภายใต้เงื่อนไขการทดลองที่กำหนด (controlled laboratory environment) |

ข้อความ limitation ภาษาอังกฤษของ Blueprint §15.3 (Risk Model, Detection, Automated Blocking, Experimental
Environment, Recovery) ใช้ตามต้นฉบับใน `docs/report/step11-chapter.md` §8.1

---

## E. Consistency checklist ก่อนทำ DOCX (Blueprint Phase 16 + เพิ่ม)

- [ ] ชื่อโครงงานตรงกับที่ยื่น · [ ] RQ ↔ O1–O11 ↔ T1–T11 ↔ M1–M10 ↔ Conclusion เป็นสายเดียว
- [ ] Architecture ในบท 3 ตรงกับ code (รวมสิ่งที่ไม่ได้ implement) · [ ] Risk model / weight sets / thresholds ตรง § C
- [ ] Rules ตรง `config/rules.yaml` · [ ] ตัวเลขทุกตัวในบท 6 ตรง `docs/evidence/step11_metrics.md`
- [ ] ไม่มีถ้อยคำในคอลัมน์ "ห้ามเขียน" ของ § D · [ ] Code revision: T1–T10 `236ce70`, T11 `d0a346d` (บท 5)
- [ ] commit hash ในเนื้อหาหลักเฉพาะ revision ของการทดลอง (บท 5 §5.3.5, บท 6 ต้นบท) · path ใช้ได้เมื่อเป็นส่วนของ implementation/วิธีการ (บท 4–5) · SHA-256 และรายการ commit อยู่ในภาคผนวก
- [ ] front matter (ปก ชื่อโครงงาน บทคัดย่อ สารบัญ) เพิ่มตอนรวมเล่ม · ไม่รวม `phase12-results.md` และ `step11-chapter.md`
- [ ] ตาราง/รูปมีเลขและอ้างถึงในเนื้อหา · [ ] อ้างอิงครบ (pfSense, Suricata, CVSS v4.0, NIST SP 800-61)
