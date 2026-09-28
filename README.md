# Automated Network Security Monitoring and Response System

ระบบเฝ้าระวังและตอบสนองต่อเหตุการณ์ด้านความปลอดภัยของเครือข่ายแบบอัตโนมัติ (ชื่อโค้ดของโครงงาน: **ITIS**)

ระบบรับ Alert จาก **Suricata (IDS)** มาจับกลุ่มเหตุการณ์ ประเมินความเสี่ยง ตัดสินใจตามกฎ แล้วสั่ง **pfSense (Firewall)** ให้ Block
Source IP ชั่วคราว อ่านค่ากลับยืนยันว่า Block จริง ปลด Block เองเมื่อครบเวลา และบันทึกทุกขั้นตอนลงฐานข้อมูลเพื่อตรวจสอบย้อนหลัง
นอกจากนี้ยังตรวจสุขภาพของ Suricata และกู้คืนเองเมื่อหยุดทำงาน

> **ต้นแบบสำหรับห้องปฏิบัติการ (prototype) ไม่ใช่ระบบสำหรับใช้งานจริง** ระบบสั่ง Firewall จริง (เพิ่ม / ลบ IP ใน pf Table)
> ให้ใช้กับเครือข่ายทดลองเท่านั้น

---

## สารบัญ

1. [ระบบทำอะไร](#1-ระบบทำอะไร)
2. [สถาปัตยกรรม](#2-สถาปัตยกรรม)
3. [การทำงานของ 1 เหตุการณ์](#3-การทำงานของ-1-เหตุการณ์)
4. [องค์ประกอบของระบบ](#4-องค์ประกอบของระบบ)
5. [การประเมินความเสี่ยงและกฎการตัดสินใจ](#5-การประเมินความเสี่ยงและกฎการตัดสินใจ)
6. [ฐานข้อมูล](#6-ฐานข้อมูล)
7. [สภาพแวดล้อมห้องปฏิบัติการ](#7-สภาพแวดล้อมห้องปฏิบัติการ)
8. [ติดตั้งและรัน](#8-ติดตั้งและรัน)
9. [ผลการทดลองโดยสรุป](#9-ผลการทดลองโดยสรุป)
10. [โครงสร้าง Repository](#10-โครงสร้าง-repository)
11. [ข้อจำกัด](#11-ข้อจำกัด)

---

## 1. ระบบทำอะไร

| หน้าที่ | รายละเอียด |
|---|---|
| รับเหตุการณ์ | อ่าน `eve.json` ของ Suricata บน pfSense แบบ Real-time ผ่าน SSH แยก Alert กับ stats |
| จับกลุ่ม (Correlation) | รวม Alert จาก Source IP เดียวกัน ครบอย่างน้อย **5 ครั้งภายใน 10 วินาที** จึงนับเป็น Pattern |
| ประเมินความเสี่ยง | ให้คะแนน 0–100 จาก 4 ปัจจัย: Severity, Frequency, Temporal, Context |
| ตัดสินใจ | กฎแบบ First Match → `BLOCK` / `ALERT` / `NO_AUTO_BLOCK` / `MONITOR` โดย Allowlist มีผลก่อนเสมอ |
| ตอบสนอง | สั่ง `pfctl` เพิ่ม IP ลง pf Table แล้ว**อ่านกลับยืนยัน** (read-back) ว่า IP อยู่ใน Table จริง |
| ปลด Block | ปลดเองเมื่อครบ **300 วินาที** และยืนยันว่าปลดจริง ตอนเริ่มระบบจะปลด Block ที่หมดอายุค้างไว้ (Startup Reconciliation) |
| ดูแลตัวเอง | ตรวจ Suricata ทุก 15 วินาที ถ้าหยุดทำงานจะ restart ได้สูงสุด 3 ครั้ง ถ้าไม่สำเร็จจะเข้าสถานะ CRITICAL และหยุดลอง |
| บันทึก | ทุกขั้นตอนลง SQLite 8 ตาราง ย้อนดูได้ว่าการ Block แต่ละครั้งมาจาก Alert ไหน คะแนนเท่าไร และกฎข้อใด |

**ต่างจาก IPS อย่างไร:** IPS อยู่ในเส้นทางของทราฟฟิก และตัดสินใจทีละแพ็กเก็ตว่าควรทิ้งหรือไม่ ส่วนระบบนี้อยู่นอกเส้นทาง
ใช้ Suricata แค่ตรวจจับ แล้วตัดสินใจจาก Alert หลายตัวรวมกันว่า **Source นี้ควรถูก Block ไหม นานเท่าไร Block ได้จริงไหม และเพราะอะไร**

---

## 2. สถาปัตยกรรม

```
 Kali / สคริปต์ทดสอบ           pfSense (FreeBSD)                              Windows Host (Engine)
 ───────────────────   ───────────────────────────────────────   ─────────────────────────────────────────
  ทราฟฟิก / inject ───► em2 ──► Suricata ──► eve.json ──(SSH tail -F)──► EVE Reader
                                                                          │ alert                │ stats
                                                                          ▼                      ▼
                                                                   Correlation Engine       Health Monitor
                                                                          │ pattern              │ DEGRADED
                                                                          ▼                      ▼
                                                                   Risk Engine (S,F,T,C)    Recovery Manager
                                                                          │ score                │ restart (SSH)
                                                                          ▼                      │
                                                                   Rule Engine ─► decision        │
                                                                          │ BLOCK                │
                       pf table ITIS_BLOCK_TEST ◄──(SSH pfctl add/show)── pfSense Enforcer        │
                       block drop in on em2                               │                      │
                                                                   Block Lifecycle ◄── Lifecycle Runner (ทุก 1 s)
                                                                          │
                                                                   SQLite audit (8 ตาราง) + logs/engine.log
```

Engine ทำงานใน Process เดียว แบ่งเป็น 3 Thread

| Thread | รอบการทำงาน | หน้าที่ |
|---|---|---|
| Main | ทุกครั้งที่มี Event | อ่าน eve.json แล้วส่งเข้า Pipeline (จับกลุ่ม → ประเมิน → ตัดสินใจ → Block) |
| Lifecycle Runner | ทุก 1 วินาที | ปลด Block ที่ครบเวลา ลองซ้ำได้ไม่เกิน 3 ครั้งถ้าปลดไม่สำเร็จ |
| Health Runner | ทุก 15 วินาที | ตรวจว่า Suricata ยังทำงานและมี stats ใหม่ ถ้าไม่ใช่ก็สั่งกู้คืน |

Main และ Lifecycle Runner ใช้ Lock ร่วมกัน เพื่อไม่ให้การ Block และการปลด Block ของ IP เดียวกันทำงานซ้อนกัน

---

## 3. การทำงานของ 1 เหตุการณ์

ตัวอย่างจริงจากการทดสอบ: Kali ส่ง TCP SYN ไปพอร์ต 22 จำนวน 10 ครั้ง ห่างกัน 0.5 วินาที

1. Suricata ตรวจพบด้วย Rule `sid 1000101` แล้วเขียน Alert (severity 1 = HIGH) ลง `eve.json`
2. EVE Reader อ่านบรรทัดใหม่ผ่าน SSH แล้วบันทึกลง `security_events`
3. Correlation Engine เห็น Alert จาก IP เดียวกันครบ 5 ครั้งภายใน 2 วินาที จึงสร้าง Pattern
4. Risk Engine ให้คะแนน S = 75, F = 70, T = 100, C = 80 ได้ **79.5 (HIGH)** เมื่อใช้ Weight Set A
5. Rule Engine พบว่าตรงกับ **RULE-001** จึงตัดสินใจ `BLOCK` 300 วินาที พร้อมบันทึกเหตุผล
6. Enforcer สั่ง `pfctl -t ITIS_BLOCK_TEST -T add <ip>` แล้วอ่านกลับด้วย `-T show` ได้ผล `SUCCESS / VERIFIED`
7. ทราฟฟิกจาก IP นั้นถูกตัดที่ em2 (ping และการเชื่อมต่อพอร์ต 22 ไม่ผ่าน)
8. ครบ 300 วินาที Lifecycle Runner ปลด Block แล้วยืนยันว่า IP หายจาก Table (`UNBLOCK / VERIFIED`) ทราฟฟิกกลับมาผ่านได้

---

## 4. องค์ประกอบของระบบ

| Module (`security_engine/`) | หน้าที่ |
|---|---|
| `ingestion/eve_reader.py` | เปิด SSH แล้วรัน `stdbuf -oL tail -n 0 -F eve.json` แยก alert / stats และ normalize |
| `correlation/engine.py` | Sliding window ต่อ Source IP, min_events, cooldown 10 วินาทีต่อ Source |
| `scoring/risk.py` | แปลงค่า S / F / T / C เป็นคะแนน, Weight Set A / B / C, Risk Level |
| `policy/rule_engine.py`, `rules_config.py` | โหลดและตรวจ `rules.yaml` แล้วประเมินแบบ First Match |
| `policy/allowlist.py`, `assets.py`, `source_context.py` | Allowlist และบริบทของ Source (factor C) |
| `enforcement/pfsense_enforcer.py` | `pfctl` add / delete / show ผ่าน SSH พร้อม read-back ตรวจรูปแบบ IP ก่อนส่งทุกครั้ง |
| `lifecycle/` | สถานะ Block (`ACTIVE` / `EXPIRED` / `REMOVE_FAILED`), หมดอายุ, ปลด Block, reconcile ตอนเริ่มระบบ |
| `storage/schema.py`, `repository.py` | Schema 8 ตาราง (WAL + Foreign Key) และจุดเดียวที่เขียน SQL |
| `health/` | ตรวจ Process (`pgrep`) + อายุของ stats, restart ไม่เกิน 3 ครั้ง, ค้างสถานะ CRITICAL |
| `pipeline.py` | ร้อยขั้นตอนของ 1 Event และบันทึกลงฐานข้อมูลก่อนสั่ง pfSense เสมอ |
| `experiment/timestamp_sink.py` | บันทึกเวลาแต่ละขั้นลง `experiment_timestamps` เมื่อรันในโหมดทดลอง |
| `settings.py`, `logging_config.py` | โหลดและตรวจ config ทั้งหมดจุดเดียว (ค่าผิดจะเกิด `ConfigError` ก่อนแตะ pfSense) |

---

## 5. การประเมินความเสี่ยงและกฎการตัดสินใจ

**สูตร:** `Risk Score = S×wS + F×wF + T×wT + C×wC` (แต่ละปัจจัยมีค่า 0–100 และน้ำหนักรวมกันได้ 1)

| ปัจจัย | การแปลงค่า |
|---|---|
| S – Severity | severity 1 (High) → 75 · 2 (Medium) → 50 · 3 (Low) → 25 · 0 (กำหนดเอง) → 100 |
| F – Frequency | 1 ครั้ง → 20 · 2–3 → 40 · 4–5 → 70 · มากกว่า 5 → 100 |
| T – Temporal | ≤ 10 วินาที → 100 · ≤ 30 → 75 · ≤ 60 → 50 · มากกว่า 60 → 25 |
| C – Context | อยู่ใน Allowlist → 0 · Known Lab Asset → 30 · Unknown / External → 80 |

| Weight Set | wS | wF | wT | wC | ลักษณะ |
|---|---|---|---|---|---|
| A (ค่าเริ่มต้น) | 0.40 | 0.25 | 0.20 | 0.15 | Baseline |
| B | 0.30 | 0.30 | 0.25 | 0.15 | เน้นพฤติกรรม (ถี่และเร็ว) |
| C | 0.50 | 0.20 | 0.15 | 0.15 | เน้นความรุนแรงของ Signature |

Risk Level: `LOW` 0–29 · `MEDIUM` 30–59 · `HIGH` 60–79 · `CRITICAL` 80–100 (ใช้รายงานผลเท่านั้น)

**กฎ (`config/rules.yaml`) ตรวจตามลำดับ กฎแรกที่ตรงจะถูกใช้**

| ลำดับ | Rule | เงื่อนไข | การตอบสนอง |
|---|---|---|---|
| 1 | RULE-003 | Source อยู่ใน Allowlist | `NO_AUTO_BLOCK` + ALERT + Audit |
| 2 | RULE-001 | Severity ≥ HIGH, ≥ 5 เหตุการณ์, ภายใน 10 วินาที | `BLOCK` 300 วินาที |
| 3 | RULE-002 | Severity ≥ MEDIUM, ≥ 5 เหตุการณ์, ภายใน 10 วินาที | `ALERT` |
| – | Default | ไม่ตรงกฎใด | `MONITOR` |

กฎตัดสินจากความรุนแรง จำนวนครั้ง ช่วงเวลา และ Allowlist **ไม่ได้ใช้ Risk Score เป็นเงื่อนไข** คะแนนความเสี่ยงจึงเป็นข้อมูลประกอบ
สำหรับอธิบายและเปรียบเทียบเหตุการณ์ ส่วน `ALERT` / `CRITICAL` ถูกบันทึกลงฐานข้อมูลและ Log เท่านั้น ยังไม่มีการส่งแจ้งเตือนออกภายนอก

---

## 6. ฐานข้อมูล

SQLite (โหมด WAL + Foreign Key) ย้อนจากคำสั่ง Block กลับไปหา Alert ต้นทางได้ครบสาย

| ตาราง | เก็บอะไร |
|---|---|
| `security_events` | Alert ทุกตัวที่อ่านได้จาก Suricata |
| `correlated_patterns` | กลุ่มเหตุการณ์ที่ถึงเกณฑ์ |
| `risk_assessments` | คะแนน S / F / T / C, weight_set, risk_score |
| `decisions` | rule_id, decision และเหตุผลที่อ่านได้ |
| `actions` | คำสั่งที่ส่งไป pfSense พร้อม `command_result` และ `verify_result` |
| `active_blocks` | IP ที่ถูก Block อยู่ เวลาหมดอายุ และสถานะ |
| `recovery_events` | ประวัติการกู้คืน Suricata |
| `experiment_timestamps` | เวลาแต่ละขั้นในโหมดทดลอง (ใช้คำนวณ Latency) |

---

## 7. สภาพแวดล้อมห้องปฏิบัติการ

| องค์ประกอบ | รายละเอียด |
|---|---|
| Host | Windows 11 · รัน Engine และ SQLite · GNS3 2.2.58.1 บน VMware Workstation 17.6.4 |
| Firewall | pfSense CE 2.7.2 · pf Table `ITIS_BLOCK_TEST` + Rule `block drop in on em2 from <ITIS_BLOCK_TEST>` |
| IDS | Suricata 7.0.8 (Package บน pfSense) ตรวจที่ em2 · เปิด EVE output และ Perf Stats (stats ทุก 10 วินาที) |
| Engine | Python 3.14.5 · PyYAML 6.0.3 · ติดต่อ pfSense ผ่าน SSH (key-based) ทาง WAN |
| Test Attacker | Kali Linux ต่อกับ em2 |

---

## 8. ติดตั้งและรัน

### ความต้องการ

- Python 3 (ทดสอบบน 3.14.5 เท่านั้น)
- OpenSSH client และ SSH key ที่ pfSense ยอมรับ
- สำหรับรัน Engine จริง: pfSense + Suricata ตามหัวข้อ 7 โดยต้องสร้าง pf Table และ Firewall Rule ที่อ้าง Table นั้นก่อน
  (การเพิ่ม IP ลง Table อย่างเดียวยังไม่ Block อะไร)

### ติดตั้ง

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` มี PyYAML (runtime dependency เดียวของ Engine) ส่วน pytest และ matplotlib ใช้ตอนพัฒนาและวิเคราะห์ผลเท่านั้น

### รันชุดทดสอบ (ไม่ต้องมีห้องปฏิบัติการ)

```bash
python -m pytest -q
```

ผลที่คาด: `828 passed, 10 skipped` รายการที่ skip คือ Integration Test ที่ต้องต่อ pfSense จริง (ทำงานเมื่อตั้ง `ITIS_PFSENSE_HOST`)
ถ้า Console ของ Windows แสดงภาษาไทยไม่ได้ ให้ตั้ง `PYTHONIOENCODING=utf-8`

### รัน Engine (ต้องมีห้องปฏิบัติการ)

1. ตั้ง Environment Variable (ดู `.env.example`) ข้อมูลการเชื่อมต่อไม่เก็บใน Repository

   ```powershell
   $env:ITIS_PFSENSE_HOST = "admin@<pfsense-ip>"                      # จำเป็น
   $env:ITIS_EVE_PATH     = "/var/log/suricata/<instance>/eve.json"   # ไม่บังคับ (override eve.path)
   ```

2. ตรวจ `config/config.yaml` ทุกครั้ง โดยเฉพาะ `system.db_path` เพื่อไม่ให้เขียนทับฐานข้อมูลของการทดลอง
3. รัน

   ```powershell
   cmd /c ".venv\Scripts\python.exe run_phase4.py < NUL"                              # โหมดปกติ
   cmd /c ".venv\Scripts\python.exe run_phase4.py --test-id T4 --run-id T4-R03 < NUL"  # โหมดทดลอง
   ```

   ตรวจใน `logs/engine.log` ว่ามีบรรทัด `เริ่มอ่าน EVE จาก ...` และ path ถูกต้อง หยุดด้วย Ctrl+C

> **ทำไมต้อง `< NUL` บน Windows:** ssh ของ Windows ที่ Engine เรียกเพื่อตรวจ Suricata และสั่ง `pfctl` จะได้ stdin เป็น Console
> ของหน้าต่างที่รัน Engine ซึ่งทำให้ค้างเป็นบางครั้งหลังคำสั่งทำงานเสร็จ (ทดสอบซ้ำ 600 ครั้งค้าง 14 ครั้ง เมื่อใช้ `< NUL` ค้าง 0 ครั้ง)
> ผลคือ Engine เข้าใจว่า Suricata หยุดและสั่ง restart โดยไม่จำเป็น หรือ Block สำเร็จจริงแต่บันทึกว่าล้มเหลว
>
> ถ้าใช้ Git Bash ต้อง `export MSYS_NO_PATHCONV=1` ก่อน ไม่เช่นนั้น path ที่ขึ้นต้นด้วย `/` จะถูกแปลงเป็น path ของ Windows

### เครื่องมือสำหรับการทดลอง

```bash
python scripts/generate_test_events.py --list                         # รายการ Scenario T1–T11
python scripts/generate_test_events.py --test-id T4 --run 3 --spacing 0
```

ชุดทดลองหลักส่ง Output ของสคริปต์ต่อท้าย `eve.json` บน pfSense ผ่าน SSH ขณะที่ Engine ทำงานอยู่ (Controlled EVE Injection)
ขั้นตอนทั้งหมดอยู่ใน `docs/test_plan.md` ส่วนการทดสอบด้วยทราฟฟิกจริงอยู่ใน `docs/evidence/RT/real_traffic_runbook.md`

---

## 9. ผลการทดลองโดยสรุป

### ชุดทดลองหลัก T1–T11 (58 รอบ, Controlled EVE Injection)

| Test | Scenario | ผลที่ได้ | รอบ |
|---|---|---|---|
| T1 | ทราฟฟิกปกติ | MONITOR | 5/5 |
| T2 | MEDIUM × 1 | MONITOR | 5/5 |
| T3 | MEDIUM × 5 ใน 10 วินาที | RULE-002 → ALERT (69.5 HIGH) | 5/5 |
| T4 | HIGH × 5 ใน 10 วินาที | RULE-001 → BLOCK → VERIFIED (79.5 HIGH) | 5/5 |
| T5 | เหมือน T4 แต่อยู่ใน Allowlist | RULE-003 → NO_AUTO_BLOCK (67.5 HIGH) | 5/5 |
| T6 | Auto-Unblock | BLOCK → UNBLOCK VERIFIED หลัง 300 วินาที | 5/5 |
| T7 | Read-back verification | `pfctl -T show` ยืนยัน IP อยู่ใน Table | 5/5 |
| T8 | หยุด Suricata | DEGRADED → Restart → HEALTHY | 5/5 |
| T9 | หยุด Suricata + Restart ใช้ไม่ได้ | ล้ม 3 ครั้ง → CRITICAL → หยุดลอง (ไม่มีครั้งที่ 4) | 5/5 |
| T10 | HIGH × 1 หรือ × 4 (ต่ำกว่าเกณฑ์) | MONITOR | 10/10 |
| T11 | เหมือน T4 · Weight Set A / B / C | 79.5 / 80.5 / 78.5 · BLOCK ทุกชุด | 3/3 |

- T1–T10 ผ่านครบ **55/55** รอบ · Block และยืนยันผลได้ **18/18** · ไม่มี Block ในกรณีที่ไม่ควร Block **0/25** · Allowlist ไม่ถูก Block **5/5**
- เวลาตั้งแต่เกิดเหตุการณ์จนถึง Block ยืนยันแล้ว (M4, T4): เฉลี่ย **1,593.4 ms** มัธยฐาน 1,584.1 ms
  ประมาณ 58% อยู่ที่การส่ง Event เข้าระบบ 37% อยู่ที่การสั่ง pfSense ผ่าน SSH และการตัดสินใจใช้ประมาณ 4%

### การทดสอบด้วยทราฟฟิกจริง RT-1 ถึง RT-3 (Kali → em2)

| Test | ทราฟฟิก | ผล |
|---|---|---|
| RT-1 (3 ครั้ง) | TCP SYN × 10 | RULE-001 BLOCK VERIFIED → ping / nc ไม่ผ่าน → ปลดเองหลัง 300.5–301.0 วินาที → กลับมาผ่านได้ |
| RT-2 | TCP SYN × 4 | ไม่ถึงเกณฑ์ ไม่เกิด Pattern ไม่ Block |
| RT-3 | TCP SYN × 10 + อยู่ใน Allowlist | RULE-003 NO_AUTO_BLOCK ไม่ Block |

ผลของ RT เป็นการยืนยันการทำงานกับแพ็กเก็ตจริง ไม่ได้นำไปรวมกับตัวเลขของชุดหลัก

ฐานข้อมูลของชุดทดลองหลัก (`data/step11_experiment.db`) ไม่อยู่ใน Repository ตรวจความถูกต้องได้ด้วย SHA-256
`d4ffe24457eb1e64723bd4b8c72a42bf6de81f9a074a3c0061a9a2087039b805`

---

## 10. โครงสร้าง Repository

| Path | หน้าที่ |
|---|---|
| `run_phase4.py` | Entry point ของ Engine |
| `security_engine/` | โค้ดของระบบ (หัวข้อ 4) |
| `config/` | `config.yaml` (ค่าระบบ), `rules.yaml` (กฎ), `allowlist.yaml`, `assets.yaml` |
| `.env.example` | ตัวอย่าง Environment Variable |
| `tests/`, `conftest.py` | Unit / Integration Test (pytest) |
| `scripts/generate_test_events.py` | สร้าง EVE Event ของ Scenario T1–T11 (สร้าง Input อย่างเดียว ไม่ตัดสินผล) |
| `run_experiment.py`, `analysis/` | Runner และ Analyzer ของช่วงพัฒนา (Phase 12) ไม่ใช่ชุดข้อมูลหลัก |
| `experiments/` | ผลต่อรอบของชุดทดลองหลัก (`results_step11.csv`) และแม่แบบ |
| `docs/test_plan.md` | Protocol ของการทดลองที่ล็อกไว้ก่อนทดลอง |
| `docs/evidence/` | หลักฐานต่อรอบของ T1–T11 และ `RT/` (runbook, สคริปต์ตรวจ DB และผลดิบของ RT) |
| `docs/report/` | รายงานบทที่ 1–7 (Markdown) ภาคผนวก และรูปประกอบ |

`data/`, `logs/` และ `.env` อยู่ใน `.gitignore`

---

## 11. ข้อจำกัด

- ทดสอบในห้องปฏิบัติการจำลอง ไม่ได้ทดสอบกับเครือข่ายจริงหรือทราฟฟิกปริมาณมาก
- ชุดทดลองหลักใช้การ Inject เหตุการณ์จาก Source เดียว ทราฟฟิกจริงใช้เฉพาะ RT จาก Kali เครื่องเดียว
- Evaluation Model และ Weight เป็นค่าที่โครงงานกำหนด ไม่ใช่มาตรฐานสากล และเพราะเกณฑ์ Correlation ทำให้ F = 70 และ T = 100 เสมอ
  คะแนนในการทดลองจึงต่างกันได้จาก S และ C เท่านั้น
- การ Block มีผลเฉพาะทราฟฟิกขาเข้าที่ em2 ตาม Firewall Rule ที่ตั้งไว้
- การกู้คืน Suricata ลองซ้ำ 3 ครั้งติดกันโดยไม่เว้นช่วงรอ เมื่อคำสั่ง restart ล้มเหลว
- ถ้า SSH ที่ใช้อ่าน `eve.json` จบลง Engine จะหยุดทั้งระบบ ไม่มีการเชื่อมต่อใหม่อัตโนมัติ
- ยังไม่ได้ติดตั้ง Prometheus / Grafana จึงไม่ได้วัดการใช้ทรัพยากร และไม่ได้เทียบเวลากับการตอบสนองด้วยมือ
