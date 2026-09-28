# บทที่ 4 การพัฒนาระบบ

บทที่ 3 อธิบายว่าระบบ**ออกแบบให้ทำอะไร** บทนี้อธิบายว่าแต่ละส่วน**ถูก implement อย่างไร** ใน source code และไฟล์ตั้งค่าจริง
โดยยกเฉพาะโค้ดหรือ pseudocode ที่ช่วยอธิบายกลไกสำคัญ

## 4.1 เครื่องมือและโครงสร้างโปรเจกต์

| รายการ | ค่า |
|---|---|
| ภาษา | Python 3 (tested on Python 3.14.5) |
| runtime dependency | PyYAML เท่านั้น (อื่น ๆ ใช้ standard library: `sqlite3`, `subprocess`, `threading`, `ipaddress`, `logging`) |
| dependency สำหรับพัฒนา/วิเคราะห์ | pytest, matplotlib (ไม่ใช่ส่วนของ engine) |
| การเชื่อมต่อ pfSense | OpenSSH client (`ssh -T -o BatchMode=yes`) ด้วย key-based authentication |
| ฐานข้อมูล | SQLite 3 (WAL mode) |

```
Project-ITIS/
├── run_phase4.py            # entry point: โหลด config, ประกอบ component, เริ่ม thread, วน EVE stream
├── config/
│   ├── config.yaml          # ค่าระบบทั้งหมด (correlation, block, health, recovery, risk, eve, system)
│   ├── rules.yaml           # กฎการตัดสินใจ
│   ├── allowlist.yaml       # source ที่ห้าม auto-block
│   └── assets.yaml          # known lab assets (ว่างโดยตั้งใจ)
├── security_engine/         # module ตามตาราง 3.8
├── scripts/generate_test_events.py   # สร้าง EVE event สำหรับการทดลอง (บทที่ 5)
└── tests/                   # unit / integration tests
```

## 4.2 Configuration

ค่าระบบทั้งหมดอยู่ใน `config/config.yaml` และโหลดผ่าน `settings.load_settings()` เพียงจุดเดียว module อื่นรับค่าที่ตรวจแล้วเป็น object
ที่มีชนิดข้อมูลกำกับ ไม่อ่าน YAML เอง หลักการที่ implement:

- **ตรวจตอนโหลด ไม่ใช่ตอนใช้** — key ที่หาย, ชนิดข้อมูลผิด หรือค่าต่ำกว่าขั้นต่ำ ทำให้เกิด `ConfigError` พร้อมชื่อ key ก่อนที่ engine จะแตะ pfSense
  หรือสร้างฐานข้อมูล เช่น `risk.weight_set` ต้องเป็น A, B หรือ C เท่านั้น ไม่ fallback เป็น A แบบเงียบ ๆ
- **ข้อมูลการเชื่อมต่อมาจาก environment เท่านั้น** — `ITIS_PFSENSE_HOST` (จำเป็น) และ `ITIS_EVE_PATH` (override path ของ EVE)
  ไม่เก็บใน repository
- กฎการตัดสินใจอยู่ใน `rules.yaml` แยกจาก code รองรับเงื่อนไขแบบประกาศค่า (`min_severity`, `min_same_src_events`,
  `max_time_window_sec`, `source_in_allowlist`) ไม่มีการประเมิน expression

ค่าที่ตั้งค่าไว้ต้องถูกส่งต่อถึง component ที่ใช้จริง ระหว่างการทดลองพบว่า entry point บันทึก `risk.weight_set` ลง log แต่ไม่ได้ส่งเข้า pipeline
ทำให้ทุกการคำนวณใช้ Set A แม้ตั้งค่าเป็นชุดอื่น ข้อบกพร่องนี้ถูกแก้ก่อนการทดลอง sensitivity (T11) พร้อมเพิ่ม test ที่ยืนยันว่าค่าจาก config ถึง pipeline
(รายละเอียดผลกระทบต่อการทดลองในบทที่ 5)

## 4.3 EVE JSON Ingestion

`ingestion/eve_reader.py` เปิด SSH ไปยัง pfSense แล้วรัน

```
stdbuf -oL tail -n 0 -F <eve_path>
```

- `-n 0` อ่านเฉพาะบรรทัดใหม่หลังเริ่มทำงาน, `-F` ตามไฟล์ต่อเมื่อถูกหมุนเวียน, `stdbuf -oL` ให้ส่งออกทีละบรรทัดไม่ค้างใน buffer
- ใช้ `ssh -T` (ไม่ขอ terminal) และปิด stdin เพื่อไม่ให้ output ผิดรูป
- แต่ละบรรทัดถูก parse เป็น JSON และแยกตาม `event_type`: `alert` ถูก normalize เป็น dict ภายใน (`src_ip`, `dst_ip`, `signature`,
  `signature_id`, `severity`, `timestamp`) พร้อมเติม `received_at` = เวลาที่ engine อ่านบรรทัดนั้น (นาฬิกาของเครื่องที่รัน engine),
  `stats` ถูกส่งให้ callback `on_stats` ของ health monitor, ประเภทอื่นถูกทิ้ง
- บรรทัดที่ parse ไม่ได้ถูกบันทึกเป็น warning และข้าม ไม่ทำให้ stream หยุด

## 4.4 Pipeline

`pipeline.py` ประมวลผล alert ทีละรายการตามลำดับต่อไปนี้ (ย่อจาก `SecurityPipeline.process()`)

```text
process(event):
    repository.save_security_event(event)              # 1 บันทึกก่อนทุกอย่าง
    pattern = correlator.process(event)
    if pattern is None: return                         # ยังไม่ถึงเกณฑ์ -> ไม่มี decision
    context = source_context_resolver.resolve(pattern.src_ip)
    risk = calculate(pattern, context, weight_set)
    decision = rule_engine.decide(risk, pattern)
    t_decision = now()
    save pattern -> risk -> decision                   # 2 audit chain ก่อน enforcement
    if decision in (ALERT, NO_AUTO_BLOCK): save action ALERT
    if decision == BLOCK:
        with lock:                                     # กัน race กับ lifecycle runner
            t_block_cmd = now()
            result = lifecycle.block(decision)
            if result.success: t_block_verified = now()
    emit(trace)                                        # -> experiment_timestamps (โหมดทดลอง)
```

main thread วนอ่าน EVE stream และเรียก `process()` ส่วน lifecycle runner และ health runner เป็น thread แยก pipeline ถือ lock ร่วมกับ
lifecycle runner เพื่อไม่ให้การ block และการ unblock ของ source เดียวกันทำงานซ้อนกัน

## 4.5 Correlation

`correlation/engine.py` เก็บ `deque` ของ (timestamp, event) แยกตาม `src_ip`

```text
process(event):
    bucket[src].append((ts, event))
    while bucket[src][0].ts < ts - window: bucket[src].popleft()     # sliding window 10 s
    if len(bucket[src]) < min_events: return None                     # < 5
    if last_emit[src] and ts - last_emit[src] < cooldown: return None # cooldown 10 s
    last_emit[src] = ts
    return Pattern(src, window_start=bucket[0].ts, window_end=ts,
                   event_count=len(bucket), max_severity=min(severities))
```

เวลาที่ใช้คือ `timestamp` ของ event (เวลาที่เหตุการณ์เกิด) ไม่ใช่เวลาที่ engine อ่าน ข้อมูลของ source ที่เก่ากว่า window + cooldown ถูกลบเป็นระยะ
เพื่อไม่ให้หน่วยความจำโตไม่จำกัด

## 4.6 Risk Engine

`scoring/risk.py` implement ตาราง 3.2–3.4 เป็น lookup function แยกต่อปัจจัย (`factor_severity`, `factor_frequency`, `factor_temporal`,
`factor_context`) แล้วรวมด้วยน้ำหนักของชุดที่เลือก

```python
S = factor_severity(pattern.max_severity)
F = factor_frequency(pattern.event_count)
T = factor_temporal(pattern.window_seconds)
C = factor_context(source_context)
R = round(S*w["severity"] + F*w["frequency"] + T*w["temporal"] + C*w["context"], 2)
```

- factor C รับ `SourceContext` ที่ resolve มาแล้วจาก `policy/source_context.py` ซึ่งรายงานสถานะ `allowlisted` และ `known_asset` ตามจริง
  ส่วนลำดับ allowlist ก่อน known asset ตัดสินใน `factor_context()` risk engine ไม่อ่านไฟล์เอง
  ทำให้ทดสอบได้โดยไม่แตะ filesystem
- `weight_set` ที่ไม่ใช่ A/B/C ทำให้เกิด `ValueError` ทันที
- ผลลัพธ์ `RiskResult` มีชื่อ field ตรงกับคอลัมน์ของ `risk_assessments` และบันทึก `weight_set` ทุกครั้ง เพื่อให้ทราบว่าคะแนนมาจากชุดใด
- ค่าอ้างอิง (S = 75, F = 70, T = 100, C = 80, Set A → 79.5) ถูกควบคุมด้วย regression test

## 4.7 Rule Engine

`policy/rules_config.py` โหลดและตรวจ `rules.yaml` (id และ priority ไม่ซ้ำ, action ที่รู้จัก, condition field ที่รองรับ, threshold > 0)
แล้วเรียงตาม priority
`policy/rule_engine.py` ประเมินแบบ first match:

```python
allowlisted = src_ip in self.allowlist
for rule in self.rules:                          # เรียงตาม priority แล้ว
    if rule.matches(pattern, allowlisted):
        return Decision(action=rule.action, rule_id=rule.id, ...,
                        reason=self._reason(rule, pattern, allowlisted))
return Decision(action=default_action, rule_id=DEFAULT_RULE_ID, ...)
```

`rule.matches()` ตรวจเฉพาะค่าจาก pattern (severity, จำนวน, ช่วงเวลา) และสถานะ allowlist ส่วน `risk_level` และ `risk_score` ถูกคัดลอกเข้า `Decision`
เพื่อบันทึกเท่านั้น `_reason()` สร้างคำอธิบายที่อ่านได้ เช่น `[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=…s (ต้อง ≤ 10s)
+ allowlisted=False` ซึ่งถูกบันทึกลง `decisions.reason`

## 4.8 pfSense Enforcer และ Verification

`enforcement/pfsense_enforcer.py` รันคำสั่งผ่าน `subprocess.run(["ssh", ..., host, "pfctl", ...])` โดยประกอบ argument เป็น list เอง
(ไม่รับ string คำสั่งจากภายนอก) และตรวจความถูกต้องของ IP ด้วย `ipaddress` ก่อนส่งทุกครั้ง

```python
def add_block(self, ip):
    ip = validate_ip(ip)                                   # 1 validate ก่อนแตะ pfSense
    rc, _ = self._run(["pfctl", "-t", self.table, "-T", "add", ip])
    command_ok = (rc == 0)
    verified = self.is_blocked(ip)                         # 2 read-back เสมอ
    status = "ENFORCED" if (command_ok and verified) else "FAILED"
    return EnforcementResult("add", ip, command_ok, verified, status)
```

`remove_block()` ทำแบบเดียวกันด้วย `-T delete` และ verify ว่า IP**หายไป**จาก table ส่วน `is_blocked()` อ่าน `pfctl -T show` แล้ว parse
เป็น set ของ IP SSH timeout (10 s), ไม่พบคำสั่ง ssh หรือ `pfctl show` ล้มเหลว ถูกแปลงเป็น `EnforcementError` ไม่ถูกตีความว่าสำเร็จ

`add_block()` ส่งคำสั่งและตรวจผลในการเรียกครั้งเดียว ข้อมูลเวลาที่ระบบบันทึกจึงมีเพียงจุดก่อนเรียก (`t_block_cmd`) และหลังได้ผลที่ verify แล้ว
(`t_block_verified`) ไม่มีจุดเวลาคั่นระหว่างการส่งคำสั่งกับการอ่านกลับ

## 4.9 Lifecycle / Auto-Unblock

`lifecycle/block_lifecycle.py` (`BlockLifecycleManager`) เป็นตัวกลางระหว่าง decision, enforcer และ `BlockStore` (ตาราง `active_blocks`)

```text
block(decision):
    existing = store.get_block(ip)
    if existing.status == ACTIVE:        return DuplicateBlockResult   # ไม่ยิงซ้ำ ไม่เลื่อน expires_at
    if existing.status == REMOVE_FAILED: return RemovalPendingResult   # ต้องปลดของเดิมให้ได้ก่อน
    result = enforcer.add_block(ip)
    if result.success:
        store.add_block(ip, blocked_at=now, expires_at=now + decision.block_duration, status=ACTIVE)
    return result

expire_due(now):                           # เรียกโดย lifecycle runner ทุก 1 s
    for blk in store.get_expired_blocks(now):   try_remove(blk.ip)
    for blk in store.get_blocks_by_status(REMOVE_FAILED):
        if not exhausted(blk.ip):               try_remove(blk.ip)       # retry ≤ 3

try_remove(ip):
    result = enforcer.remove_block(ip)
    status = EXPIRED if result.verified else REMOVE_FAILED
    record action UNBLOCK (ผูกกับ decision เดิมที่สั่ง BLOCK)
```

- ระยะเวลาปิดกั้นมาจาก `decision.block_duration` (ค่าใน `rules.yaml`) ไม่ hard-code
- `reconcile()` ถูกเรียกครั้งเดียวตอน engine เริ่มทำงาน และใช้ตรรกะเดียวกับ `expire_due()` เพื่อปลด block ที่หมดอายุระหว่างที่ engine ไม่ได้ทำงาน
- `LifecycleRunner` เป็น thread ที่เรียก `expire_due()` ด้วย `stop_event.wait(1.0)` จึงหยุดได้ทันทีเมื่อ shutdown และ exception ในรอบหนึ่งถูก log
  โดยไม่ทำให้ thread หยุด

## 4.10 SQLite Audit Log

`storage/schema.py` สร้างตารางทั้ง 8 (ตาราง 3.7) ด้วย `CREATE TABLE IF NOT EXISTS` และตั้ง `PRAGMA journal_mode=WAL` กับ
`PRAGMA foreign_keys=ON` ทุก connection (SQLite ปิด foreign key เป็นค่าเริ่มต้น) `storage/repository.py` (`AuditRepository`) เป็นจุดเดียว
ที่เขียน SQL ส่วน pipeline และ lifecycle เรียกผ่าน method เช่น `save_security_event`, `save_correlated_pattern`, `save_risk_assessment`,
`save_decision`, `save_alert_action`

- เวลาทุกค่าบันทึกเป็น ISO 8601 UTC
- ความล้มเหลวของการบันทึก (`AuditPersistenceError`) ถูกแยกจากความล้มเหลวของ enforcement และบันทึกเป็น error โดยไม่ทำให้ engine หยุด
- `active_blocks.action_id` ชี้ไปยัง action BLOCK ที่ทำให้เกิด block นั้นเสมอ (ไม่ถูกเขียนทับด้วย UNBLOCK) จึงย้อนกลับถึง decision, risk และ pattern ได้

## 4.11 Health Monitor และ Recovery

- `health/suricata_controller.py` — ตรวจ process ด้วย `pgrep -x suricata` และสั่ง restart ด้วยคำสั่งจาก `health.restart_command`
  (`/usr/local/etc/rc.d/suricata.sh restart`) ผ่าน SSH
- `health/monitor.py` — `check()` รวมผลการตรวจ process กับอายุของ stats ล่าสุด (`last_stats_at` ที่ได้จาก `on_stats`) เป็น HEALTHY/DEGRADED
  และ `check(since=t)` ใช้ `stats.uptime` ตัดสินว่า stats มาจาก process ที่เริ่มหลังเวลา t หรือไม่
- `health/recovery.py` — วนไม่เกิน `max_attempts`:

```text
for attempt in 1..3:
    restart = controller.restart()
    if restart.ok:
        status = await_functional(restarted_at)     # ตรวจทุก 5 s ไม่เกิน 30 s
        if status.healthy: record SUCCESS; return HEALTHY
    result = CRITICAL if attempt == 3 else FAIL
    record(attempt, result, error)
return CRITICAL                                     # ไม่มี attempt ที่ 4
```

  เมื่อคำสั่ง restart คืนค่าไม่สำเร็จ loop จะไปยัง attempt ถัดไป**ทันที**โดยไม่มีช่วงรอ (การรอมีเฉพาะหลัง restart สำเร็จ) ในกรณีที่ restart
  ล้มทุกครั้ง attempt ทั้งสามจึงเกิดต่อเนื่องในเวลาสั้นมาก
- `health/runner.py` — thread ที่เรียก `tick()` ทุก 15 s ถ้า DEGRADED จะเรียก recovery ถ้าเข้า CRITICAL จะ latch สถานะไว้ (`CRITICAL_IS_LATCHED`)
  และไม่เรียก recovery ซ้ำจนกว่า health จะกลับเป็น HEALTHY เอง engine และ pipeline ยังทำงานต่อ

## 4.12 Logging

`logging_config.py` ตั้งค่า logging จาก `system.log_path` และ `system.log_level` เขียนลง `logs/engine.log` ในรูปแบบ
`<UTC time> <LEVEL> <module> :: <message>` ทุก module ใช้ logger ของตนเอง ข้อผิดพลาดใน thread หรือในการบันทึกถูก log พร้อม exception
เหตุการณ์สำคัญ (การตัดสินใจ, ผล enforcement, สถานะสุขภาพ, recovery) มีบรรทัด log ที่ใช้เป็นหลักฐานประกอบฐานข้อมูลได้

## 4.13 Experiment Instrumentation

เมื่อรัน entry point ด้วย `--test-id` และ `--run-id` (เช่น `--test-id T4 --run-id T4-R03`) engine จะสร้าง `ExperimentTimestampSink`
ที่รับ trace จาก pipeline แล้วบันทึกลง `experiment_timestamps` หนึ่งแถวต่อ pattern ที่ผ่าน correlation

- run_id ต้องอยู่ในรูป `<test_id>-R<NN>` และตรงกับ test_id มิฉะนั้น engine ไม่เริ่มทำงาน
- ค่าเวลาถูก**คัดลอกจาก trace เดียวกับที่ pipeline ใช้ตัดสินใจ** ไม่สร้างใหม่และไม่ประกอบย้อนหลังจากตารางอื่น
- alert ที่ไม่ถึงเกณฑ์ correlation ไม่มีแถว, block ที่ถูกระงับมี `t_block_cmd` เป็นค่าว่าง, verify ไม่ผ่านมี `t_block_verified` เป็นค่าว่าง
- ถ้าไม่ระบุ `--test-id` engine ทำงานตามปกติโดยไม่บันทึกตารางนี้ (ไม่เปลี่ยนตรรกะของ pipeline)

## 4.14 การทดสอบซอฟต์แวร์

ชุดทดสอบใช้ pytest มี 38 ไฟล์ ครอบคลุมทุก module ผลรันล่าสุด **828 passed, 10 skipped** (10 รายการที่ skip คือ integration test ที่ต้องต่อ
pfSense จริง และทำงานเมื่อตั้ง `ITIS_PFSENSE_HOST` เท่านั้น)

**ตาราง 4.1** กลุ่มของการทดสอบ

| กลุ่ม | ตัวอย่างไฟล์ | สิ่งที่ตรวจ |
|---|---|---|
| Configuration | `test_settings`, `test_runtime_config`, `test_rules_config` | key ครบ, ชนิด/ช่วงค่า, env override, weight set ถึง pipeline |
| Ingestion | `test_eve_reader` | แยก alert/stats, normalize, บรรทัดเสีย |
| Correlation / Risk / Rule | `test_correlation`, `test_risk`, `test_sensitivity`, `test_rule_engine`, `test_allowlist`, `test_assets` | window, min_events, cooldown, lookup, golden case 79.5, ชุด A/B/C, first match, allowlist override |
| Enforcement / Lifecycle | `test_pfsense_enforcer`, `test_block_lifecycle*`, `test_block_duplicate`, `test_block_expiry`, `test_block_remove_failed`, `test_lifecycle_runner` | read-back, ACTIVE หลัง verify เท่านั้น, duplicate, หมดอายุ, retry ≤ 3, reconcile |
| Audit | `test_schema`, `test_repository`, `test_audit_chain`, `test_pipeline_audit` | 8 ตาราง, foreign key, audit ก่อน enforcement, สายย้อนกลับ |
| Health / Recovery | `test_health_monitor`, `test_recovery`, `test_health_runner`, `test_suricata_controller` | PROCESS_DOWN/EVE_STALE, stats ของ process ใหม่, ไม่มี attempt ที่ 4, CRITICAL latch |
| Integration / Experiment | `test_integration_pipeline`, `test_wiring`, `test_timestamp_sink`, `test_experiment_timestamps`, `test_pfsense_integration` | ประกอบระบบครบ, FR-15, run identity, pfSense จริง (skip เมื่อไม่มี lab) |

การทดสอบใช้ fake enforcer และ fake clock แทน pfSense และเวลาจริง ทำให้ทดสอบกรณีหมดอายุ 300 s และกรณีคำสั่งล้มเหลวได้โดยไม่ต้องรอหรือไม่ต้องมี lab
ส่วนการทำงานกับ pfSense และ Suricata จริงยืนยันด้วยการทดลองในบทที่ 5
