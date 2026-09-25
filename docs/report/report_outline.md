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

## B. โครงสร้างเล่ม

### บทที่ 1 บทนำ
1.1 ที่มาและความสำคัญ (IDS ตรวจจับได้แต่ตอบสนองด้วยมือ · single alert อาจเป็น FP · automated block ต้องมี safety/audit/reversibility — Blueprint §1.3)
1.2 Problem statement · 1.3 **Research Question** (อ้างตามต้นฉบับภาษาอังกฤษ)
1.4 วัตถุประสงค์ — **ตาราง 1.1 O1–O11**
1.5 ขอบเขต — in-scope / out-of-scope (Blueprint §1.5) · 1.6 ประโยชน์ที่คาดว่าจะได้รับ · 1.7 ข้อจำกัดเบื้องต้น

### บทที่ 2 ทฤษฎีและงานที่เกี่ยวข้อง
2.1 Firewall และ pfSense (pf tables) · 2.2 IDS และ Suricata (rules, severity, EVE JSON) · 2.3 Event correlation
2.4 Risk assessment (CVSS v4.0 — severity concept; NIST SP 800-61 — incident handling) — ต้องมี disclaimer §1.6
2.5 Rule-based automated response และ safety control (allowlist, temporary block, verification)
2.6 Service health monitoring/recovery · 2.7 Audit trail · 2.8 งานที่เกี่ยวข้อง (SOAR/IPS — เพื่อวางตำแหน่ง ไม่ใช่เทียบผล)

### บทที่ 3 การวิเคราะห์และออกแบบระบบ
3.1 ภาพรวม architecture (Suricata = เห็น · Python = คิด · pfSense = ทำ · SQLite = จำ) — **ตาราง 3.1 Components**
3.2 Data flow: EVE → ingestion → correlation → risk → rule → enforcement → verify → audit → lifecycle (unblock)
3.3 Sequence diagram event → block → unblock · 3.4 Correlation (source IP + window 10 s + min_events 5 + severity)
3.5 Risk Model — **ตาราง 3.2** weights + lookup S/F/T/C + level thresholds (ดู § C) · 3.6 Decision rules — **ตาราง 3.3**
3.7 Allowlist (สองชั้น: C = 0 ในชั้น risk + RULE-003 override) · 3.8 Temporary block/lifecycle (300 s, reconcile ตอน start)
3.9 Enforcement verification (read-back) · 3.10 Health/recovery (PROCESS_DOWN/EVE_STALE, retry ≤ 3, CRITICAL latch)
3.11 Database schema 8 ตาราง (ER diagram) · 3.12 Fail-safe behaviour

### บทที่ 4 การพัฒนาระบบ
4.1 โครงสร้าง project · 4.2 ingestion (`eve_reader.py`, SSH tail) · 4.3 correlation (`correlation/engine.py`)
4.4 risk (`scoring/risk.py`) · 4.5 rule engine (`policy/rule_engine.py`, `config/rules.yaml`)
4.6 source context (`policy/allowlist.py`, `assets.py`, `source_context.py`) · 4.7 enforcement (`pfsense_enforcer.py`: SSH + pfctl)
4.8 lifecycle (`lifecycle/*`) · 4.9 audit (`storage/*`) · 4.10 health/recovery (`health/*`)
4.11 configuration (`config/config.yaml`, env vars NFR-07) · 4.12 logging · 4.13 experiment instrumentation (FR-15 `timestamp_sink.py`)
4.14 testing (unit/integration, 828 passed / 10 skipped — skip = ต้องมี pfSense จริง)
→ ใช้ snippet/pseudocode เฉพาะจุดสำคัญ ไม่ใส่ source ทั้งไฟล์

### บทที่ 5 การทดลองและวิธีประเมินผล
5.1 สภาพแวดล้อม (pfSense 2.7.2, Suricata 7.0.8, GNS3/VMware, Windows host) — ตาราง hardware/software
5.2 Network topology · 5.3 วิธีป้อน input: **controlled EVE injection เป็นหลัก** (Kali = supplementary เท่านั้น)
5.4 **ตาราง 5.1 T1–T11** (scenario, input, expected, จำนวน run) · 5.5 **M1–M10** (นิยาม + แหล่งข้อมูล)
5.6 Timestamp methodology (same-host SEC01, FR-15) + clock observation · 5.7 ขั้นตอนต่อ run (engine ใหม่ทุก run)
5.8 Dataset freeze และ validation (เขียนเป็นข้อความ — hash/commit อยู่ใน evidence repo) · 5.9 วิธีวิเคราะห์ (สถิติเชิงพรรณนา)

### บทที่ 6 ผลการทดลองและอภิปรายผล
6.1 **ตาราง 6.1 Functional results T1–T11** · 6.2 **ตาราง 6.2 Latency M1–M4** + รูป M4 breakdown
6.3 **ตาราง 6.3 Success/safety M5–M10** (M10 = T8, T9 แยก) · 6.4 T11 sensitivity · 6.5 ตาราง O1–O11
6.6 Discussion (6 ประเด็นใน step11-chapter §6) · 6.7 Findings F1–F5 · 6.8 Limitations (Blueprint §15.3 + L1–L10)

### บทที่ 7 สรุปและข้อเสนอแนะ
7.1 ตอบ RQ · 7.2 สรุปสิ่งที่ระบบทำได้ · 7.3 สรุปผลการทดลอง · 7.4 ข้อจำกัด · 7.5 Future work

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
- [ ] ไม่มี commit hash / SHA-256 / path ภายในในเนื้อหาหลัก (ย้ายไปภาคผนวกหรือ evidence)
- [ ] ตาราง/รูปมีเลขและอ้างถึงในเนื้อหา · [ ] อ้างอิงครบ (pfSense, Suricata, CVSS v4.0, NIST SP 800-61)
