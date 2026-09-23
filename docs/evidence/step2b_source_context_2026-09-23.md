# STEP 2B — Source Context Integration (factor C)

วันที่: 2026-09-23 · commit: `b8dd672 feat: integrate source context into experiment pipeline`
ขอบเขต: implementation evidence ของ STEP 2B — **ไม่ใช่ผลการทดลอง T1–T11**

ป้ายกำกับในเอกสารนี้: **[observed]** = ผลที่วัด/อ่านได้จริง · **[config]** = ค่าที่ตั้งไว้ ·
**[decision]** = ข้อตัดสินใจของผู้วิจัย · **[interpretation]** = การตีความ

## 2B.1 Asset discovery

คำถาม: `192.168.1.10` และ `192.168.1.11` (ที่เคยถูกอ้างเป็น candidate asset) มีอยู่จริงใน lab หรือไม่

**[observed]** ตรวจแบบอ่านอย่างเดียวบน pfSense (192.168.227.150) หลัง boot ~2 นาที เวลา ~22:32 (+07):

| แหล่ง | คำสั่ง | ผล |
|---|---|---|
| ARP | `arp -an \| grep -E '192\.168\.1\.(10\|11)[^0-9]'` | ไม่พบ (exit 1) |
| DHCP leases | `grep -E -A8 'lease 192\.168\.1\.(10\|11) ' /var/dhcpd/var/db/dhcpd.leases` | ไม่พบ (exit 1) — ไฟล์มีเพียง lease `192.168.1.100` (binding state free, 2026-09-02) |
| pfSense config | `grep -n -E '192\.168\.1\.(10\|11)[^0-9]' /conf/config.xml` | ไม่พบ (exit 1) |
| ARP ทั้งตาราง | `arp -an` | บน em1 (LAN) มีเพียง `192.168.1.1` (interface ของ pfSense เอง) |

**[observed]** ค้นเพิ่ม: repo (source/config/docs) ไม่พบสอง IP นี้ · Blueprint (`Project ITIS.pdf`) ไม่มี IP ใดเลยทั้งเล่ม

**[interpretation]** ARP table หลัง boot ไม่นานอาจยังไม่ครบ (เครื่องที่ปิดอยู่จะไม่ปรากฏ) — ผลนี้จึง
บอกว่า "ไม่มีหลักฐาน" ไม่ได้พิสูจน์ว่า "ไม่มีเครื่อง"

**[decision]** `192.168.1.10` / `.11` ถือเป็น retired reference — ไม่ใช้เป็น asset และไม่เปิด VM ไล่หา
ไม่สร้าง asset จากการเดาเพื่อให้ได้ C=30 · `192.168.2.10` (Kali / attacker) ไม่ใช่ known asset

## 2B.2 Asset configuration

**[config]** `config/assets.yaml` = `assets: []` (ว่างโดยตั้งใจ พร้อม comment อธิบายเหตุผล)

loader `security_engine/policy/assets.py::load_assets()` ใช้ policy strict แบบเดียวกับ `load_allowlist()`:
ไฟล์หาย / YAML เสีย / top-level ไม่ใช่ mapping / ไม่มี key `assets` / ค่าไม่ใช่ list /
entry ไม่ใช่ string / IP ไม่ถูกต้อง -> `AssetsError` · IP ถูก canonicalize · ซ้ำ -> dedupe · ว่าง/null -> `set()`

## 2B.3–2B.4 Resolver เข้า pipeline (ทั้งสอง runner)

ก่อน STEP 2B: `run_experiment.py` และ `run_phase4.py` ไม่ส่ง resolver -> pipeline ใช้
`UnknownSourceContextResolver` -> ทุก source ได้ C=80 รวมถึง source ที่ allowlist
(RULE-003 ยังตัดสินถูก แต่ risk evidence ผิด: 79.5 แทน 67.5)

หลัง STEP 2B:

```
config/allowlist.yaml ─┐
                       ├─ load_source_context() ─> (allowlist, StaticSourceContextResolver)
config/assets.yaml ────┘                              │                │
                                          RuleEngine(allowlist)   SecurityPipeline(source_context_resolver)
                                               RULE-003                 factor C
```

- allowlist ชุดเดียวกันไปทั้ง RuleEngine และ resolver (สร้างจากฟังก์ชันเดียว)
- `run_experiment.py`: ลบ `ALLOWLISTED_SRC = "203.0.113.9"` ออก · source ของ T5 = IP ใน allowlist
  (prerequisite P6) · allowlist ว่าง + ขอรัน T5 -> `ValueError` ก่อนเขียน trace/DB ใด ๆ ·
  เพิ่ม `--allowlist` / `--assets`
- `run_phase4.py::build_pipeline()`: เพิ่ม `assets_path` และส่ง resolver เข้า pipeline

## 2B.5–2B.6 Test

**[observed]** `pytest -q` -> **748 passed, 10 skipped** (baseline ก่อน STEP 2B: 712 passed, 10 skipped)

| สิ่งที่พิสูจน์ | test |
|---|---|
| unknown -> C=80, golden 79.5 | `test_unknown_source_context`, `test_golden_risk_case`, `test_unknown_pattern_end_to_end[×2]` |
| allowlisted -> C=0, risk 67.5 (ไม่เป็น 0) | `test_allowlisted_source_context`, `test_allowlisted_risk_not_zero`, `test_allowlisted_pattern_end_to_end[×2]` |
| allowlisted -> RULE-003 NO_AUTO_BLOCK | `test_allowlisted_decision_uses_rule_003` |
| model รองรับ known asset C=30 (tmp file, TEST-NET IP) | `test_known_asset_context` |
| config ของ repo -> ทุก source C=80 | `test_repo_config_resolves_every_source_as_unknown` |
| runner ส่ง resolver + allowlist ชุดเดียวกัน | `test_runner_passes_resolver[run_phase4/run_experiment]` |
| สอง runner ให้ context เดียวกัน | `test_both_runners_use_same_context` |
| loader strict | `tests/test_assets.py` (18 tests) |
| T5 ไม่มี P6 -> fail ก่อนเขียนผล | `test_t5_without_p6_allowlist_raises`, `test_run_t5_with_empty_allowlist_fails_before_writing` |

end-to-end tests จับ `RiskAssessment` ที่ pipeline คำนวณจริง (spy บน `calculate`) ผ่าน pipeline
ที่สร้างจาก runner ทั้งสองตัว

## ข้อจำกัด (สำหรับ Report — Discussion/Limitations)

ไม่มี Lab asset ที่ยืนยัน role ได้ใน subnet 192.168.1.0/24 จาก topology ปัจจุบัน จึงไม่มี
test case สำหรับ C=30 ในชุดการทดลองนี้ ค่า C=30 ยังคงเป็นส่วนหนึ่งของ Risk Model เพื่อรองรับ
known-asset context แต่ไม่ได้ถูกใช้เป็น experimental condition ใน T1–T11

## นอกขอบเขต commit นี้ (ยังค้าง)

- `scripts/generate_test_events.py:31` ยังมี `ALLOWLISTED_SRC = "203.0.113.9"` (comment อ้างว่า
  "ต้องตรงกับ config/allowlist.yaml") — generator เป็นคนละส่วนกับ runner จะแก้พร้อมงาน
  generator/test constant (8 -> 10) ใน commit แยก
