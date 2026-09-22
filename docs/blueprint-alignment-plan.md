# Blueprint Alignment Plan

> **Source of truth:** `Project ITIS.pdf` — *Master Project Blueprint & Implementation Guide*
> **จุดตั้งต้น:** `feature/phase11-12 @ ff9ac58` (152 passed / 10 skipped)
> **คู่กับ:** `blueprint-gap-matrix.md` (ผลการตรวจ) — เอกสารนี้คือแผนปิด gap
> ทุก commit หลังจากนี้ต้องอ้าง STEP number ของเอกสารนี้

## หลักที่ใช้จัดลำดับ

```
config layer  →  core logic  →  persistence  →  runtime features  →  experiment  →  analysis
   (อ่านค่า)        (คำนวณ)         (บันทึก)          (ทำงานจริง)          (เก็บข้อมูล)      (รายงาน)
```

**กฎ:** ห้ามข้ามไป STEP ถัดไปถ้า test suite ยังไม่กลับมาเขียว · ห้ามรัน T1–T11 ก่อน STEP 1–10 เสร็จ
เพราะจะเป็นการเก็บ experimental data จากระบบที่ยังไม่ conform กับ frozen requirements

---

## ข้อตัดสินใจที่ล็อกแล้ว (2026-09-22)

| # | ประเด็น | ข้อสรุป |
|---|---|---|
| 1 | YAML parser | **เพิ่ม `PyYAML` + สร้าง `requirements.txt`** — เป็น third-party dependency ตัวแรกของ production code ตาม §3.3 ที่ระบุทั้ง `requirements.txt` และไฟล์ `.yaml` 3 ตัว |
| 2 | `eve_path` อยู่ที่ไหน | **`config.yaml` เป็นค่าหลัก, env override ได้** — precedence: `ITIS_EVE_PATH` > `config.yaml:eve_path` ส่วน `ITIS_PFSENSE_HOST` คงอยู่ที่ env ตาม NFR-07 |
| 3 | เอกสารชุดนี้ | เขียนลง `docs/` และ commit ก่อนแตะโค้ดบรรทัดแรก |

### ยังไม่ตัดสิน (ไม่บล็อก STEP 1)

| # | ประเด็น | ต้องตัดสินก่อน |
|---|---|---|
| A | แหล่ง asset list ของ factor C (§3.5 ระบุ Known Asset=30 / Unknown-External=80 แต่ blueprint ไม่ได้บอกว่าเก็บที่ไหน) ตัวเลือก: key ใน `config.yaml` · ไฟล์ `config/assets.yaml` · ใช้ RFC1918 เป็นเกณฑ์ | STEP 2 |
| B | สถานะของ `REMOVE_FAILED` — ไม่มีใน blueprint (`ACTIVE`/`EXPIRED`/`MANUALLY_REMOVED`) แต่จำเป็นจริงตาม NFR-06 จะ map หรือเก็บเป็นส่วนขยายพร้อม rationale | STEP 4 |
| C | ขอบเขต Prometheus / Grafana — in-scope ตาม blueprint (Phase 13, 10 panels) แต่ไม่มี metric ใดใน M1–M10 ที่ต้องใช้ | STEP 13 |

---

## STEP 0 — Freeze หลักฐานก่อน (ไม่แตะโค้ด)

| | |
|---|---|
| ทำอะไร | `git tag pre-freeze-phase12 ff9ac58` + เขียน `docs/report/phase12-prefreeze-note.md` |
| เนื้อหา note | dataset Phase 12 มาจาก implementation ก่อน alignment และ risk model ยังไม่ตรง §3.5 |
| evidence | `docs/evidence/P12-*` ไม่แตะ |
| ปิด requirement | ไม่ปิดข้อไหน — กันไม่ให้ Phase 15 อ้างตัวเลขข้ามยุคปนกัน |

---

## STEP 1 — Config layer

| | |
|---|---|
| ไฟล์ใหม่ | `requirements.txt`, `config/config.yaml`, `config/rules.yaml`, `config/allowlist.yaml`, `security_engine/settings.py` |
| ไฟล์แก้ | `run_phase4.py` (อ่านผ่าน settings), `.env.example` |
| ไฟล์ลบ | `config/allowlist.txt` → แทนที่ด้วย `allowlist.yaml` |
| key ที่ต้องมีใน `config.yaml` | `eve_path`, `poll_interval`, `correlation.window_sec=10`, `correlation.min_events=5`, `risk.weight_set=A`, `risk.weights{A,B,C}`, `block.duration_sec=300`, `recovery.max_retry=3`, `recovery.check_interval=15`, `recovery.stats_stale_multiplier=3`, `db_path`, `log_level` |
| test ใหม่ | `tests/test_settings.py` — โหลดครบทุก key / ลบ key ใดก็ raise ชัดเจน / type validation / env override precedence / weight set A/B/C |
| test ที่ต้องแก้ | `tests/test_runtime_config.py` (env-only → config + env) |
| exit criteria | `python -c "from security_engine.settings import load_config; load_config()"` ผ่าน และลบ key ใดออกแล้ว raise |
| ปิด | **NFR-01**, ส่วน config ของ §3.3 |

**บันทึกการตัดสินใจใน STEP 1**

- `EXPIRE_INTERVAL_SEC` (block-expiry polling) **ไม่เข้า `config.yaml`** — เป็น implementation-level
  scheduler parameter ไม่ใช่ Blueprint experiment/configuration parameter
  และห้ามเอา `health.check_interval_sec=15` (FR-12) มาใช้แทนเพราะคนละความหมาย
- `config/rules.yaml` และ `config/allowlist.yaml` สร้างเป็น configuration artifact เท่านั้นใน STEP 1
  runtime ยังอ่าน rules ที่ hardcode และ `config/allowlist.txt` จนถึง STEP 3
- `security_engine/experiment/experiment_config.py` มีค่าซ้ำกับ `config.yaml` โดยตั้งใจ
  (`CORRELATION_WINDOW` / `MIN_EVENTS` / `PROD_BLOCK_DURATION`) — จะรวมศูนย์ใน STEP 10

## STEP 2 — Risk Model v1 ให้ตรง §3.5

| | |
|---|---|
| ไฟล์แก้ | `security_engine/scoring/risk.py` |
| เปลี่ยน | `factor_frequency` → lookup 20/40/70/100 · `factor_temporal` → lookup ≤10s=100 / ≤30s=75 / ≤60s=50 / >60s=25 · `factor_target_concentration` → `factor_context` (Known Asset=30 / Unknown-External=80 / Allowlisted=0) · weight set A/B/C อ่านจาก config |
| test เขียนใหม่ | `tests/test_risk.py` — 14 จาก 22 tests assert ค่าของสูตรเดิม (`test_frequency_exact_min_is_100`, `test_temporal_full_window_zero`, `test_temporal_half_window_is_50`, `test_concentration_*`) จะ fail โดยตั้งใจ |
| test ที่ต้องรันยืนยัน | `test_rule_engine.py`, `test_integration_pipeline.py`, `test_allowlist.py` — decision ควรคงเดิม (T4 ยัง BLOCK, T5 ยัง NO_AUTO_BLOCK) ต้องพิสูจน์ ไม่ใช่สมมติ |
| ต้องตัดสินก่อน | ข้อ A (asset list) |
| ปิด | **§3.5 (F, T, C)** เตรียม **T11** |

**หมายเหตุ boundary:** `factor_context` ต้องรู้จัก allowlist + asset list ทำให้ `risk.py` รับ input ใหม่
ไม่ขัด D4 (allowlist ไม่ลบ risk score — C=0 กระทบแค่ 15% ของสูตร) แต่เป็นการเปลี่ยน module boundary ที่ต้องตั้งใจ
**แก้โดยไม่ให้ `risk.py` โหลดไฟล์เอง**: resolve เป็น `SourceContext` จากภายนอกแล้ว inject เข้า
`calculate(pattern, source_context, weight_set)` (dependency injection)

### STEP 2A — Risk Model alignment (ทำแล้ว)

`security_engine/models.py` (`CorrelationPattern`, `SourceContext`) ·
`security_engine/policy/source_context.py` (Protocol + static/unknown resolver) ·
`risk.py` ใช้ lookup ตาม §3.5 + Weight Set A/B/C · `tests/test_sensitivity.py`

**Semantic ที่ล็อกแล้ว (หลักฐาน: §5 Step 5.1 "Context จาก asset/allowlist status" + §3.5
"Known Asset = อยู่ใน asset list ของ Lab (มีโอกาส FP สูง)" + golden case 79.5)**

```
Factor C = SOURCE context        allowlisted -> 0 | known lab asset -> 30 | unknown/external -> 80
```
allowlist มีผลสองชั้นโดยตั้งใจ: ลด C ในชั้น Risk (ไม่ทำให้ score เป็น 0) และเป็น safety
override ที่ RULE-003 ในชั้น Rule Engine — Risk ≠ Decision

**Golden case ที่ต้องผ่านเสมอ**: S=75 F=70 T=100 C=80 ด้วย Set A -> **79.5 -> HIGH**

**Sensitivity finding (เก็บไว้สำหรับ Report ไม่ใช่ bug)**: pattern เดียวกัน
Set A=79.5 HIGH · Set B=80.5 CRITICAL · Set C=78.5 HIGH — ข้าม threshold 80 ที่ Set B
แต่ decision เป็น BLOCK ทั้งสาม set เพราะ RULE-001 ครอบ "HIGH หรือสูงกว่า"

### STEP 2B — Asset discovery + resolver integration (ยังไม่ทำ, รอ lab online)

**Known limitation ของ STEP 2A ที่ต้องปิดใน 2B:**

- `UnknownSourceContextResolver` เป็น **temporary fallback** ไม่ใช่ production asset
  classification — ถือว่าทุก source เป็น unknown/external (C=80) ซึ่ง conservative
  (ไม่ลดความเสี่ยงให้ใครเพราะขาดข้อมูล) แต่ไม่ใช่ความจริงของ lab
- **`run_experiment.py` ยังไม่ส่ง resolver เข้า `SecurityPipeline`** ดังนั้นถ้ารัน experiment
  ตอนนี้ scenario allowlisted (A4/T5) จะได้ **C=80 -> risk 79.5** แทนที่จะเป็น
  **C=0 -> risk 67.5** — decision ยังถูก (RULE-003 จับ allowlist เอง) แต่ **risk evidence จะผิด**
  จึงห้ามใช้ผล risk จาก runner ปัจจุบันเป็นหลักฐานของ Phase 14
- ลำดับที่ต้องทำ: สำรวจ asset จริงของ lab -> `config/assets.yaml` -> resolver ที่อ่าน
  assets.yaml + allowlist -> ต่อเข้า `run_experiment.py` และ `run_phase4.py` -> integration validation

*Integrate SourceContextResolver into the experiment runner after assets.yaml is
established from actual lab asset discovery.*

## STEP 3 — Rule engine อ่าน `rules.yaml`

| | |
|---|---|
| ไฟล์แก้ | `security_engine/policy/rule_engine.py` (โหลดจากไฟล์, priority-ordered, first-match wins, default MONITOR), `security_engine/policy/allowlist.py` (อ่าน `.yaml`) |
| test | 26 tests เดิมต้องเขียวด้วย rules จากไฟล์ + ใหม่: format ผิด → raise, สลับ priority แล้วผลเปลี่ยนตามไฟล์ |
| ปิด | **§3.6, FR-05, FR-06** (logic), NFR-01 ส่วน rules |

## STEP 4 — SQLite 8 tables + WAL

| | |
|---|---|
| ไฟล์ใหม่ | `security_engine/storage/schema.py` (DDL ครบ 8 ตารางตาม §3.4), `security_engine/storage/audit_store.py` |
| ไฟล์แก้ | `security_engine/lifecycle/block_store.py` — `active_blocks` ปัจจุบันขาด `action_id` และ status ไม่ตรง blueprint |
| test | `tests/test_schema.py` — 8 ตารางครบ, FK ถูก, `PRAGMA journal_mode` คืน `wal`, parameterized query only; `test_block_store.py` แก้ตาม status ใหม่ |
| ต้องตัดสินก่อน | ข้อ B (`REMOVE_FAILED`) |
| ปิด | **§3.4, NFR-05** เตรียม FR-04/07/13/14/15 |

## STEP 5 — Pipeline เขียน audit trail ลง DB

| | |
|---|---|
| ไฟล์แก้ | `security_engine/pipeline.py` (`security_events` → `correlated_patterns` → `risk_assessments` → `decisions`), `security_engine/lifecycle/block_lifecycle.py` (`actions` + link `action_id`) |
| test | เขียนครบทุกขั้น, FK chain ไล่จาก `security_events.id` ถึง `active_blocks` ได้ในเทสเดียว, `reason` ครบ 10 field ตาม FR-14 |
| ปิด | **FR-04, FR-07, FR-14** และส่วนใหญ่ของ **O9** |

## STEP 6 — FR-10 + FR-11 (block state machine)

| | |
|---|---|
| ไฟล์แก้ | `security_engine/lifecycle/block_lifecycle.py` (duplicate guard อยู่ชั้นนี้ ไม่ใช่ pipeline), `security_engine/lifecycle/block_store.py` (เลิก `INSERT OR REPLACE` แบบเดิม), `run_phase4.py` (เรียก `reconcile()` ก่อน `runner.start()`) |
| contract ที่ล็อก | `ACTIVE` → ไม่เรียก enforcer, ไม่แตะ DB, ไม่เลื่อน `expires_at`, log duplicate, คืนผล `DUPLICATE` · `EXPIRED` / `MANUALLY_REMOVED` → block ใหม่ได้ · `REMOVE_FAILED` → reconcile ก่อน ห้าม re-block ตรง ๆ |
| test ใหม่ (9) | lifecycle: add_block ถูกเรียกครั้งเดียว · `expires_at` ไม่เปลี่ยน · 1 แถว ACTIVE · duplicate ถูกบันทึก · unblock แล้ว block ใหม่ได้ · REMOVE_FAILED ไม่ re-block<br>pipeline: pattern ซ้ำหลัง cooldown 10s ระหว่าง block 300s → ไม่มี enforcement ครั้งที่สอง (ปิดช่อง ~290 วินาที)<br>startup: entry point เรียก `reconcile()` ก่อน `runner.start()` · ACTIVE ที่ยังไม่หมดอายุต้องคงอยู่ |
| ปิด | **FR-10, FR-11** และกันไม่ให้ **M9** เพี้ยน |

## STEP 7 — EVE reader ให้ครบ FR-01 / FR-02

| | |
|---|---|
| ไฟล์แก้ | `security_engine/ingestion/eve_reader.py` — inode-aware rotation, skip malformed + log warning, แยก `event_type: alert` → pipeline / `stats` → health |
| test ใหม่ | `tests/test_eve_reader.py` — **ปัจจุบันไม่มี test ครอบไฟล์นี้เลย** (fixture EVE JSON + จำลอง rotate) |
| ปิด | **FR-01, FR-02, O1** — เงื่อนไขจำเป็นของ Mode C |

## STEP 8 — Logging + error handling

| | |
|---|---|
| ไฟล์แก้ | ทุกจุดที่ใช้ `print` (`run_phase4.py`, `run_experiment.py`) → `logging` + `logs/engine.log`, level จาก config · `.gitignore` เพิ่ม `logs/` |
| test | INFO ลงไฟล์จริง, DEBUG เปิดจาก config ได้, external call มี try/except + timeout ครบ |
| ปิด | **NFR-02, NFR-03** |

## STEP 9 — Health check + Recovery

| | |
|---|---|
| ไฟล์ใหม่ | `security_engine/recovery/suricata_health.py` — process check + EVE stats freshness × 3 + restart + retry ≤ 3 → CRITICAL |
| ไฟล์แก้ | `run_phase4.py` (health loop ขนานกับ pipeline), `audit_store` (`recovery_events`) |
| test | DEGRADED เมื่อ process ตาย / stats ค้าง · recovery สำเร็จรอบ 1-2-3 · ล้มครบ 3 → CRITICAL และ **ต้องไม่มี attempt 4** |
| ปิด | **FR-12, FR-13, O10** เตรียม **T8 / T9 / M10** |

## STEP 10 — Experiment infrastructure

| | |
|---|---|
| ไฟล์ใหม่ | `scripts/generate_test_events.py`, `experiments/results_template.csv` (23 columns ตาม §14.5), `docs/test_plan.md` (T1–T11 + Expected Result) |
| ไฟล์แก้ | `run_experiment.py` → เขียน `experiment_timestamps` (`test_id` = T1..T11), retire A1–A4 เป็น internal label พร้อมตาราง mapping |
| ปิด | **FR-15** เตรียม Phase 14 |

## STEP 11 — Phase 14: รัน T1–T11

T1–T10 × ≥ 5 รอบ · T11 × Weight Set A/B/C · evidence ลง `docs/evidence/P14-*`
ห้ามเริ่มก่อน STEP 1–10 เขียวครบ

## STEP 12 — Mode C (real Suricata path)

ไฟล์ใหม่ `run_experiment_real.py` · ปิด **M1, M4, M5** ตามนิยามจริง
(ปัจจุบัน `t0_received ≠ T_event` จึงวัดไม่ได้) · ต้องมี STEP 7 ก่อน

## STEP 13 — Phase 15: analysis + Chapter 1–3

`analysis/` อ่านจาก DB ไม่ใช่ JSONL อย่างเดียว · ตาราง O1–O11 PASS/FAIL จากผลจริงเท่านั้น
§15.3 limitations 6 หัวข้อ (blueprint เขียนข้อความภาษาอังกฤษไว้ให้แล้ว) · ต้องตัดสินข้อ C

---

## สิ่งที่ห้ามทำตลอดแผนนี้

- ห้ามสร้าง evidence ย้อนหลังจากความจำ — evidence ต้องมาจากการรันจริงเท่านั้น
- ห้ามนำคะแนน risk ก่อน STEP 2 ไปปนกับผลหลัง STEP 2
- ห้ามเขียนในรายงานว่าระบบ "ตรวจจับการโจมตีได้แม่นยำ" หรือ "ลดเวลาได้ X%"
  เพราะไม่มี manual baseline (blueprint §1.5 ระบุเองว่าวัด manual ใน lab ไม่ได้)
- ห้ามสร้าง feature เพียงเพราะ blueprint มีชื่อมันอยู่ จนกว่า matrix จะบอกว่าจำเป็นต่อ RQ / O1–O11
