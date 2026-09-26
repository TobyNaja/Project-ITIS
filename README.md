# Project ITIS

**Security Event Correlation + Risk-Based Automated Response + Security Service Recovery**
(ระบบวิเคราะห์เหตุการณ์ด้านความปลอดภัยและตอบสนองต่อภัยคุกคามแบบอัตโนมัติโดยใช้การประเมินความเสี่ยงและการกู้คืนบริการด้านความปลอดภัย)

ต้นแบบ (prototype) สำหรับห้องปฏิบัติการที่เชื่อม Suricata (IDS) กับ pfSense (firewall): อ่าน EVE JSON → correlation → risk assessment →
rule engine → ปิดกั้นชั่วคราวผ่าน pf table พร้อม read-back verification → auto-unblock → audit trail ใน SQLite และตรวจ/กู้คืน Suricata
เชิงฟังก์ชัน (retry ≤ 3)

> **ไม่ใช่ระบบสำหรับใช้งานจริง (not production-ready)** ทดสอบในห้องปฏิบัติการเสมือนที่ควบคุมได้เท่านั้น ดูหัวข้อ "ข้อจำกัด" ท้ายไฟล์

## โครงสร้าง repository — อะไรคืออะไร

| กลุ่ม | path | หน้าที่ |
|---|---|---|
| **ระบบที่รันจริง (runtime)** | `run_phase4.py` | entry point ของ engine |
| | `security_engine/` | ingestion, correlation, risk, rule engine, enforcement, lifecycle, audit, health/recovery |
| | `config/` | `config.yaml` (ค่าระบบ), `rules.yaml` (กฎ), `allowlist.yaml`, `assets.yaml` |
| | `.env.example` | ตัวอย่าง environment variable ที่ต้องตั้ง (ไม่เก็บข้อมูลการเชื่อมต่อใน repo) |
| **ชุดทดสอบซอฟต์แวร์** | `tests/`, `conftest.py` | unit / integration tests (pytest) |
| **เครื่องมือสำหรับการทดลอง** | `scripts/generate_test_events.py` | สร้าง EVE event สำหรับ T1–T11 (สร้าง input อย่างเดียว ไม่ตัดสินผล) |
| | `run_experiment.py`, `analysis/` | synthetic runner และ analyzer ของช่วงพัฒนา (Phase 12) — ไม่ใช่ชุดข้อมูลหลักของรายงาน |
| **หลักฐานการทดลอง (evidence)** | `docs/evidence/` | registry, validation, metrics, clock และหลักฐานต่อ run ของ T1–T11 (58 runs) |
| | `experiments/results_step11.csv` | ผลต่อ run |
| | `docs/test_plan.md` | experimental protocol ที่ล็อกไว้ก่อนทดลอง |
| **รายงาน** | `docs/report/` | Markdown บทที่ 1–7 + ภาคผนวก, `short/` ฉบับย่อ, `dist/` ฉบับสมบูรณ์ (DOCX/PDF) |

ฐานข้อมูลของการทดลอง (`data/step11_experiment.db`) และ log (`logs/`) **ไม่อยู่ใน repository** (อยู่ใน `.gitignore`)
ไฟล์ฐานข้อมูลที่ freeze แล้วส่งแยก และตรวจความถูกต้องได้ด้วย SHA-256 ในภาคผนวก ก ของรายงานฉบับสมบูรณ์
(`d4ffe24457eb1e64723bd4b8c72a42bf6de81f9a074a3c0061a9a2087039b805`)

## ความต้องการของระบบ

- Python 3 (ทดสอบบน Python 3.14.5 เท่านั้น — ยังไม่ได้ทดสอบบน 3.10)
- OpenSSH client และ SSH key-based authentication ไปยัง pfSense (ใช้ `ssh -T -o BatchMode=yes`)
- สำหรับรัน engine จริง: pfSense (ห้องปฏิบัติการใช้ CE 2.7.2) ที่ติดตั้ง Suricata (7.0.8), เปิด EVE output และ "Perf Stats",
  และมี pf table `ITIS_BLOCK_TEST` ที่กฎปิดกั้นอ้างถึง

## ติดตั้ง

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` มี PyYAML (runtime dependency เดียวของ engine) และ pytest, matplotlib (ใช้พัฒนา/วิเคราะห์เท่านั้น)

## รันชุดทดสอบ (ไม่ต้องมีห้องปฏิบัติการ)

```bash
python -m pytest -q
```

ผลที่คาด: `828 passed, 10 skipped` — 10 รายการที่ skip คือ integration test ที่ต้องต่อ pfSense จริง ซึ่งทำงานเมื่อตั้ง `ITIS_PFSENSE_HOST` เท่านั้น
ชุดทดสอบใช้ fake enforcer และ fake clock จึงไม่แตะ firewall จริง
(ถ้า console ของ Windows แสดงภาษาไทยไม่ได้ ให้ตั้ง `PYTHONIOENCODING=utf-8`)

## รัน engine (ต้องมีห้องปฏิบัติการ)

1. ตั้งค่าเฉพาะเครื่องเป็น environment variable (ดู `.env.example`)

   ```powershell
   $env:ITIS_PFSENSE_HOST = "admin@<pfsense-ip>"                        # required
   $env:ITIS_EVE_PATH     = "/var/log/suricata/<instance>/eve.json"     # optional: override eve.path
   ```

   ถ้าใช้ Git Bash บน Windows ต้อง `export MSYS_NO_PATHCONV=1` ก่อน มิฉะนั้น path ที่ขึ้นต้นด้วย `/` จะถูกแปลงเป็น path ของ Windows
2. ตรวจค่าใน `config/config.yaml` (correlation window 10 s, min_events 5, block 300 s, `risk.weight_set`, `health.restart_command`, `system.db_path`)
3. รัน

   ```bash
   python run_phase4.py                                   # โหมดปกติ
   python run_phase4.py --test-id T4 --run-id T4-R03      # โหมดทดลอง: บันทึก experiment_timestamps (FR-15)
   ```

   ตรวจใน `logs/engine.log` ว่ามีบรรทัด "เริ่มอ่าน EVE จาก ..." และ path ถูกต้อง หยุด engine ด้วย Ctrl+C

engine เป็นระบบที่**สั่ง firewall จริง** (เพิ่ม/ลบ IP ใน pf table) ให้ใช้กับห้องปฏิบัติการเท่านั้น และใส่ IP ที่ห้ามปิดกั้นใน `config/allowlist.yaml`

## เครื่องมือสำหรับการทดลอง

```bash
python scripts/generate_test_events.py --list                        # รายการ scenario T1–T11
python scripts/generate_test_events.py --test-id T4 --run 3 --spacing 0
```

การทดลองในรายงานใช้ controlled EVE injection: ส่ง output ของ generator ต่อท้ายไฟล์ EVE บน pfSense ผ่าน SSH ขณะที่ engine ทำงานอยู่
ขั้นตอน เงื่อนไขก่อนทดลอง (P1–P8) และ mapping ของ run_id อยู่ใน `docs/test_plan.md` และบทที่ 5 ของรายงาน

## ข้อจำกัดและหมายเหตุการใช้งาน

- ประเมินในห้องปฏิบัติการเสมือนด้วย controlled EVE injection จาก source เดียว ผลไม่แทนประสิทธิภาพระดับ production
- การยืนยันการปิดกั้นทำในระดับ pf table read-back ไม่ได้ทดสอบเส้นทางของทราฟฟิกโดยตรง
- แบบจำลองความเสี่ยงเป็น weighted model ที่ออกแบบสำหรับการทดลอง ไม่ใช่มาตรฐานสากล และไม่ใช้ตัดสินการตอบสนอง (rule engine เป็นผู้ตัดสิน)
- การกู้คืนไม่มีช่วงรอระหว่าง attempt เมื่อคำสั่ง restart ล้มเหลว
- ไม่ได้ติดตั้ง Prometheus/Grafana จึงไม่มีการวัด overhead
- ข้อจำกัดทั้งหมดอยู่ในหัวข้อ 6.8 ของรายงานฉบับสมบูรณ์
