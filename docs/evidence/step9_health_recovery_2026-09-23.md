# STEP 9 — Health / Recovery Lab Validation (FR-12 / FR-13)

วันที่: 2026-09-23 · ขอบเขต: infrastructure readiness ก่อน T1–T11 — **ไม่ใช่ผลการทดลอง**

ป้ายกำกับ: **[observed]** = วัด/อ่านได้จริง · **[config]** = ค่าที่ตั้งไว้ ·
**[decision]** = ข้อตัดสินใจของผู้วิจัย · **[interpretation]** = การตีความ

สถานะ: ส่วน A (stats path + persistence) **เสร็จ** · ส่วน B (HealthMonitor / recovery runtime) **เสร็จ** — ดู B0–B7

## Environment

**[observed]** pfSense 2.7.2 · Suricata 7.0.8 RELEASE · interface em2 (KALIINTERFACE) ·
EVE path `/var/log/suricata/suricata_em224404/eve.json` · engine รันบนคอมหลัก 192.168.227.1
อ่าน EVE ผ่าน SSH (`stream_events()`) · pfSense WAN 192.168.227.150

## A1. Root cause ของ stats ที่หายหลัง reboot

**[observed]** หลัง lab เปิดใหม่ (Suricata PID 82264, start 21:57:56) `stream_events()` ต่อ SSH ได้
ครบ 35 s แต่ `stats callbacks: 0` · eve.json mtime ค้างที่ 00:39

```
/conf/config.xml (mtime 21:46):
  <enable_stats_collection>on</enable_stats_collection>
  <stats_upd_interval>10</stats_upd_interval>
  <eve_log_stats>off</eve_log_stats>
suricata.yaml (generated 21:57): stats: enabled: yes / interval: 10
  main eve-log (eve.json) types: alert, drop, http, dns, tls, files, dhcp, ftp, ... tftp   <- ไม่มี stats
```

**[interpretation]** `stats.enabled: yes` (Suricata นับ counter) ≠ `eve_log_stats: on` (เขียน stats ลง
eve.json) · pfSense สร้าง suricata.yaml ใหม่จาก config.xml ตอน boot — ค่าที่ไม่ได้ persist ใน
config.xml จึงหาย ไม่ทราบว่าทำไมค่ารอบก่อนไม่ persist (ไม่ได้สืบต่อ — **[decision]** ไม่ใช่ blocker)

## A2. GUI Save -> config.xml -> YAML

GUI: Services → Suricata → Interfaces → KALIINTERFACE (em2) → EVE Output Settings → **Perf Stats** ✓ → Save
(แถบสีเขียว)

**[observed]** 22:12:43 (+07):
```
-rw-r--r--  39375 Sep 23 22:12 /conf/config.xml                   (เดิม 21:46)
-rw-r--r--  13293 Sep 23 22:12 .../suricata_24404_em2/suricata.yaml (เดิม 21:57 / 13205)
596: <eve_log_stats>on</eve_log_stats>
604: <eve_log_stats_totals>on</eve_log_stats_totals>
605: <eve_log_stats_deltas>off</eve_log_stats_deltas>
606: <eve_log_stats_threads>off</eve_log_stats_threads>
YAML: main eve-log เริ่มบรรทัด 105 · eve-log ตัวที่สองเริ่มบรรทัด 173
168:        - stats:
169:            totals: yes
170:            deltas: no
171:            threads: no
PID 82264 (ยังไม่ restart)  ·  /conf/backup/config-1790095814.xml  Sep 23 22:12
```

**[observed]** GUI Save ไม่ restart Suricata — PID ยังเป็น 82264 หลัง Save

## A3. Restart (ก่อน reboot)

**[observed]**
```
22:15:10  /usr/local/etc/rc.d/suricata.sh restart   -> restart_exit=0
22:15:14  pgrep -x suricata -> 60011                 (เดิม 82264)
22:16:00  stats events หลัง restart:
  2026-09-23T22:15:24.291465+0700
  2026-09-23T22:15:34.292442+0700
  2026-09-23T22:15:44.293637+0700
  2026-09-23T22:15:54.294223+0700
```

**[observed]** `verify_stream_stats.py` (35 s, scratch script — ดูหมายเหตุท้ายไฟล์):
```
stats callbacks: 3
alerts: 0
1 received= 2026-09-23T15:16:14.572019+00:00 event_timestamp= 2026-09-23T22:16:14.296607+0700 event_type= stats
2 received= 2026-09-23T15:16:24.572367+00:00 event_timestamp= 2026-09-23T22:16:24.297154+0700 event_type= stats
3 received= 2026-09-23T15:16:34.571404+00:00 event_timestamp= 2026-09-23T22:16:34.298114+0700 event_type= stats
interval_sec= 10.000348
interval_sec= 9.999037
```

## A4. Persistence across reboot

reboot pfSense (ผู้ทดลองสั่ง) — **ไม่แตะ GUI หลัง reboot**

**[observed]** 22:32:08 (+07), `uptime` = up 2 mins:
```
-rw-r--r--  39375 Sep 23 22:12 /conf/config.xml                   (ไม่ถูกเขียนทับ)
-rw-r--r--  13293 Sep 23 22:31 .../suricata.yaml                  (generated ใหม่ตอน boot)
596: <eve_log_stats>on</eve_log_stats>
512: <enable_stats_collection>on</enable_stats_collection>
515: <stats_upd_interval>10</stats_upd_interval>
YAML: stats: enabled: yes / interval: 10 · 168: - stats: (ใน main eve-log 105..172)
PID 72809  STARTED Wed Sep 23 22:31:18 2026
stats หลัง boot:
  2026-09-23T22:31:28.829010+0700   <- 10 s หลัง start
  2026-09-23T22:31:38.831092+0700
  2026-09-23T22:31:48.833028+0700
  2026-09-23T22:31:58.835357+0700
  2026-09-23T22:32:08.836075+0700
```

**[observed]** `verify_stream_stats.py` หลัง reboot:
```
stats callbacks: 4
alerts: 0
1 received= 2026-09-23T15:32:18.832846+00:00 event_timestamp= 2026-09-23T22:32:18.836745+0700 event_type= stats
2 received= 2026-09-23T15:32:28.833809+00:00 event_timestamp= 2026-09-23T22:32:28.837816+0700 event_type= stats
3 received= 2026-09-23T15:32:38.835098+00:00 event_timestamp= 2026-09-23T22:32:38.838797+0700 event_type= stats
4 received= 2026-09-23T15:32:48.835370+00:00 event_timestamp= 2026-09-23T22:32:48.839525+0700 event_type= stats
interval_sec= 10.000963
interval_sec= 10.001289
interval_sec= 10.000272
```

| ตรวจ | ก่อน reboot | หลัง reboot |
|---|---|---|
| config.xml `eve_log_stats` | on | on |
| YAML main eve-log มี `- stats` | มี | มี |
| Suricata start เอง | PID 60011 | PID 72809 |
| stats interval | ≈10.00 s | ≈10.00 s |
| `stream_events` -> `on_stats()` | 3 callbacks / alerts 0 | 4 callbacks / alerts 0 |

**สรุป A:** FR-12 stats path (EVE -> SSH `stream_events()` -> `iter_events()` -> `on_stats()`) และ
configuration persistence ผ่านในระดับ lab · ยังไม่ได้พิสูจน์ต่อถึง `HealthMonitor` / `HealthRunner`

**[config]** repo: `health.stats_interval_sec: 10`, freshness = 10 × 3 = 30 s (commit `1dae4e5`)

## A5. Clock (Windows 192.168.227.1 ↔ pfSense)

วัดด้วย `w32tm /stripchart /computer:192.168.227.150 /dataonly` — ค่าบวก = Windows ช้ากว่า

| เวลา (+07) | สถานะ | offset ที่วัดได้ |
|---|---|---|
| 22:18:31–22:18:39 | ก่อน resync | −255.9 … −254.9 ms |
| 22:19:45–22:19:53 | หลัง `w32tm /resync /force` (MaxAllowedPhaseOffset=1) | −248.4 … −248.1 ms |
| 22:26:52–22:27:00 | หลังตั้ง `MaxAllowedPhaseOffset=0` + resync (sync 22:26:36) | −0.39 … −0.30 ms |
| 22:33:02–22:33:10 | หลัง pfSense reboot | +7.00 … +7.20 ms |

**[observed]** เทียบ `time.windows.com` ในช่วงเดียวกันได้ค่าใกล้กัน (เช่น 22:33 = +7.38 … +7.60 ms)
-> pfSense สอดคล้องกับ upstream; Windows เป็นฝ่ายที่ drift

**[observed]** ค่า w32time ที่ใช้จริง (`w32tm /query /configuration`, ทุกค่า `(Local)` ไม่มี GPO):
`MaxAllowedPhaseOffset: 1` (เดิม) · `UpdateInterval: 360000` · `LargePhaseOffset: 50000000` ·
`PhaseCorrectRate: 1` · `NtpServer: time.windows.com,0x9`

**[decision]** ไม่ tune NTP เพิ่ม · ไม่ชดเชย offset ใน code · วัด offset (≥5 samples) ก่อนแต่ละชุดการทดลอง
แล้วรายงานเป็น experimental limitation · ห้ามหัก offset จาก latency อัตโนมัติ (offset ไม่คงที่)

**[config] ต้องคืนก่อน STEP 11:** `MaxAllowedPhaseOffset` ถูกเปลี่ยน 1 -> 0 ระหว่าง investigation
```
reg add HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config /v MaxAllowedPhaseOffset /t REG_DWORD /d 1 /f
w32tm /config /update
```

## B. HealthMonitor / Recovery runtime (FR-12 / FR-13 / NFR-06)

**[config]** `health.restart_command: "/usr/local/etc/rc.d/suricata.sh restart"` (commit `eeb3aab`) ·
check_interval 15 s · freshness 30 s · restart_wait 5 s · recovery.max_attempts 3

วิธีรัน: `run_phase4.main()` ผ่าน scratch wrapper ที่เปิด DEBUG เฉพาะ logger `security_engine.health`
(HEALTHY และ "ได้รับ EVE stats event" log ที่ระดับ DEBUG) — ไม่แก้ repo/config ·
env: `ITIS_PFSENSE_HOST=admin@192.168.227.150`, `ITIS_EVE_PATH=/var/log/suricata/suricata_em224404/eve.json`,
`MSYS_NO_PATHCONV=1` · DB: `data/experiment.db` (log timestamp = UTC)

### แผนที่ของ `recovery_events`

| id | timestamp (UTC) | reason | attempt | result | ประเภท |
|---|---|---|---|---|---|
| 1 | 15:59:21.790652 | EVE_STALE | 1 | FAIL | **INCIDENTAL VALIDATION RUN** — ไม่ใช่ผลทดลอง (B0) |
| 2 | 16:02:03.738799 | PROCESS_DOWN | 1 | SUCCESS | ก่อนแก้ defect — **ใช้เป็นหลักฐาน recovery ไม่ได้** (B2) |
| 3 | 16:08:24.113851 | PROCESS_DOWN | 1 | SUCCESS | 9B.3 intended (หลังแก้ defect) (B3) |
| 4 | 16:13:05.327512 | PROCESS_DOWN | 1 | FAIL | 9B.5 intended (B5) |
| 5 | 16:13:05.629961 | PROCESS_DOWN | 2 | FAIL | 9B.5 intended (B5) |
| 6 | 16:13:05.814490 | PROCESS_DOWN | 3 | CRITICAL | 9B.5 intended (B5) |

ไม่มีการลบหรือแก้ row ใดใน DB

### B0. INCIDENTAL VALIDATION RUN (15:58:41–15:59:21Z) — ไม่ใช่ผลทดลอง

**[observed]** Git Bash แปลง env `ITIS_EVE_PATH` เป็น `C:/Program Files/Git/var/log/...` -> engine tail ไฟล์ที่ไม่มี:
```
15:58:42Z INFO    เริ่มอ่าน EVE จาก admin@192.168.227.150:C:/Program Files/Git/var/log/suricata/suricata_em224404/eve.json
15:58:42Z DEBUG   health = HEALTHY (stats_age=0.8s)
15:58:57Z DEBUG   health = HEALTHY (stats_age=16.0s)
15:59:12Z WARNING health = DEGRADED (EVE_STALE, stats_age=31.1s/30s)
15:59:12Z WARNING เริ่ม recovery Suricata attempt 1/3 (EVE_STALE)
15:59:16Z INFO    สั่ง restart Suricata ... (/usr/local/etc/rc.d/suricata.sh restart)
15:59:21Z WARNING health = DEGRADED (EVE_STALE, stats_age=40.0s/30s)
15:59:21Z ERROR   recovery attempt 1/3 ล้มเหลว: functional check ยังไม่ผ่าน: EVE_STALE
15:59:21Z WARNING เริ่ม recovery Suricata attempt 2/3 (EVE_STALE)
```
engine ถูกหยุดระหว่าง attempt 2 (row ของ attempt 2 ไม่ถูกเขียน) แต่ restart ถูกสั่งไปแล้ว 2 ครั้ง ->
Suricata PID ใหม่ 48207 (22:59:26 +07) และ stats กลับมาทุก 10 s · reconcile ตอนเริ่ม engine ปิด block
ทดสอบเก่า `198.51.100.77` (หมดอายุ 2026-09-21) -> `actions` id 1 UNBLOCK SUCCESS/VERIFIED (FR-10 ปกติ;
pfSense table ว่างอยู่แล้วหลัง reboot)

**[interpretation]** โดยบังเอิญ run นี้แสดงว่า EVE_STALE path ทำงาน (ไม่มี stats > 30 s -> DEGRADED ->
recovery) และ HEALTHY ช่วง 30 s แรกนับอายุจากเวลาเริ่ม engine ไม่ได้พิสูจน์ว่ามี stats เข้ามา —
หลักฐาน stats flow ต้องดูบรรทัด "ได้รับ EVE stats event"

### B1. 9B.1 HEALTHY baseline (16:00:40Z)

**[observed]**
```
16:00:40Z INFO    เริ่มอ่าน EVE จาก admin@192.168.227.150:/var/log/suricata/suricata_em224404/eve.json
16:00:40Z DEBUG   health = HEALTHY (stats_age=0.2s)
16:00:47Z DEBUG   ได้รับ EVE stats event (uptime=80)
16:00:55Z DEBUG   health = HEALTHY (stats_age=8.5s)
16:00:57Z DEBUG   ได้รับ EVE stats event (uptime=90)
16:01:07Z DEBUG   ได้รับ EVE stats event (uptime=100)
16:01:10Z DEBUG   health = HEALTHY (stats_age=3.7s)
16:01:17Z DEBUG   ได้รับ EVE stats event (uptime=110)
16:01:25Z DEBUG   health = HEALTHY (stats_age=8.9s)
16:01:41Z DEBUG   health = HEALTHY (stats_age=4.0s)
```
ไม่มี recovery attempt · **Result: PASS** (FR-12)

### B2. 9B.2–9B.3 ก่อนแก้ defect — พบว่า recovery SUCCESS ด้วย stats ของ process เก่า

**[observed]** `STOP_AT_UTC=2026-09-23T16:01:53Z` (`suricata.sh stop` exit 0, `pgrep -x suricata` exit 1)
```
16:01:54Z DEBUG   ได้รับ EVE stats event (uptime=147)        <- stats สุดท้ายของ process เก่า
16:01:56Z WARNING health = DEGRADED (PROCESS_DOWN, stats_age=2.1s/30s)
16:01:56Z WARNING เริ่ม recovery Suricata attempt 1/3 (PROCESS_DOWN)
16:01:58Z INFO    สั่ง restart Suricata ... (/usr/local/etc/rc.d/suricata.sh restart)
16:02:03Z DEBUG   health = HEALTHY (stats_age=9.6s)           <- ยังเป็น stats uptime=147
16:02:03Z INFO    recovery Suricata สำเร็จที่ attempt 1/3
16:02:08Z DEBUG   ได้รับ EVE stats event (uptime=10)          <- stats แรกของ process ใหม่
```
**[interpretation]** functional check (+5 s) ผ่านเพราะ stats ของ process เก่ายังอายุ < 30 s —
recovery ถูกบันทึก SUCCESS (row 2) ก่อนมีหลักฐานว่า process ใหม่เขียน stats ·
**Result: DEFECT** -> แก้ใน commit `eeb3aab fix: require new-process stats before recording recovery success`:
recovery ต้องเห็น stats ที่มาหลังสั่ง restart **และ** `stats.uptime` ≤ เวลาที่ผ่านไปตั้งแต่สั่ง restart (+1 s)
poll ทุก restart_wait (5 s) เพดาน = freshness (30 s) · health ปกติ (FR-12, 30 s) ไม่เปลี่ยน

### B3. 9B.3 หลังแก้ defect — recovery SUCCESS ด้วย stats ของ process ใหม่

**[observed]** engine เริ่ม 16:07:10Z — HEALTHY ×4, stats uptime 320→350 ·
`STOP_AT_UTC=2026-09-23T16:08:06Z` (stop exit 0, pgrep exit 1)
```
16:08:07Z DEBUG   ได้รับ EVE stats event (uptime=369)        <- stats สุดท้ายของ process เก่า
16:08:11Z WARNING health = DEGRADED (PROCESS_DOWN, stats_age=3.7s/30s)
16:08:11Z WARNING เริ่ม recovery Suricata attempt 1/3 (PROCESS_DOWN)
16:08:13Z INFO    สั่ง restart Suricata ... (/usr/local/etc/rc.d/suricata.sh restart)
16:08:18Z WARNING health = DEGRADED (NO_NEW_STATS, stats_age=11.1s/30s)   <- เดิมจะนับ SUCCESS ตรงนี้
16:08:23Z DEBUG   ได้รับ EVE stats event (uptime=10)          <- process ใหม่
16:08:24Z DEBUG   health = HEALTHY (stats_age=0.2s)
16:08:24Z INFO    recovery Suricata สำเร็จที่ attempt 1/3
16:08:33Z DEBUG   ได้รับ EVE stats event (uptime=20)
```
pfSense: `pgrep -x suricata` -> 68482 (started 23:08:13 +07) · eve.json stats 23:08:23 / :33 / :43 (+07)

| | Expected | Observed |
|---|---|---|
| detection | DEGRADED | DEGRADED (PROCESS_DOWN) 5 s หลัง stop |
| recovery | restart -> process + new stats -> SUCCESS | attempt 1 SUCCESS หลังได้ stats uptime=10 |
| audit | `recovery_events` suricata / 1 / SUCCESS / UTC | row 3 |

**Result: PASS** (FR-13)

### B4. 9B.4 audit
row 3 (ด้านบน) — `service=suricata`, `attempt=1`, `result=SUCCESS`, timestamp UTC (`+00:00`) · **Result: PASS**

### B5. 9B.5 Recovery failure ×3 + CRITICAL latch

failure injection: `restart_command: "/usr/bin/false"` ใน working tree เท่านั้น (ไม่ commit, ไม่แก้ source) ·
`/usr/bin/false` บน pfSense คืน exit 1

**[observed]** engine เริ่ม 16:12:19Z — HEALTHY ×3, stats uptime 251→281 ·
`STOP_AT_UTC=2026-09-23T16:13:02Z` (stop exit 0, pgrep exit 1)
```
16:13:05Z WARNING  health = DEGRADED (PROCESS_DOWN, stats_age=2.1s/30s)
16:13:05Z WARNING  เริ่ม recovery Suricata attempt 1/3 (PROCESS_DOWN)
16:13:05Z ERROR    restart Suricata ไม่สำเร็จที่ admin@192.168.227.150: ** WARNING: connection is not using a post-quantum key exchange algorithm. ...
16:13:05Z ERROR    recovery attempt 1/3 ล้มเหลว: ** WARNING: connection is not using a post-quantum ...
16:13:05Z WARNING  เริ่ม recovery Suricata attempt 2/3 (PROCESS_DOWN)
16:13:05Z ERROR    (เหมือน attempt 1)
16:13:05Z WARNING  เริ่ม recovery Suricata attempt 3/3 (PROCESS_DOWN)
16:13:05Z ERROR    restart Suricata ไม่สำเร็จ ...
16:13:05Z CRITICAL recovery Suricata ล้มครบ 3 ครั้ง (...) — CRITICAL engine ทำงานต่อแต่ IDS อาจไม่ส่ง event แล้ว
16:13:21Z ERROR    Suricata ยังอยู่ในสถานะ CRITICAL (PROCESS_DOWN) — หยุด auto recovery รอการแก้ไขที่เครื่อง IDS
16:13:36Z ERROR    Suricata ยังอยู่ในสถานะ CRITICAL (PROCESS_DOWN;EVE_STALE) — ...
16:13:51Z ERROR    Suricata ยังอยู่ในสถานะ CRITICAL (PROCESS_DOWN;EVE_STALE) — ...
16:14:06Z ERROR    Suricata ยังอยู่ในสถานะ CRITICAL (PROCESS_DOWN;EVE_STALE) — ...
16:14:21Z ERROR    Suricata ยังอยู่ในสถานะ CRITICAL (PROCESS_DOWN;EVE_STALE) — ...
```
`grep -c "attempt 4"` บน log ทั้ง run = **0** · CRITICAL ค้าง 5 health cycles (76 s) โดยไม่มี restart ใหม่

| | Expected | Observed |
|---|---|---|
| attempts | 3 แล้วหยุด | 3 (rows 4–6) |
| attempt 4+ | ไม่มี | ไม่มี (0 ครั้งตลอด 5 cycles) |
| final state | CRITICAL | CRITICAL + log CRITICAL |
| engine | ทำงานต่อ (ไม่ fail-stop) | health loop ทำงานต่อทุก 15 s |

**Attempt 3 is recorded as CRITICAL by design because it is the final permitted recovery attempt; it
represents an unsuccessful third attempt and transition to terminal CRITICAL state.** สำหรับ M10:
recovery attempt failure = attempt ที่ไม่ใช่ SUCCESS (FAIL และ final CRITICAL) · run นี้:
attempts 3 · successful 0 · failed 3 · final state CRITICAL

**Result: PASS** (FR-13 retry ≤ 3, CRITICAL latch)

**[observed] defect ของ audit ที่พบใน run นี้:** `recovery_events.error` ของ rows 4–6 เป็นข้อความ warning ของ
ssh ล้วน ๆ — exit code 1 ของ `/usr/bin/false` หายไป (controller ใช้ stderr แทน rc ถ้า stderr ไม่ว่าง
และ ssh client เขียน post-quantum notice ลง stderr ทุกครั้ง) -> แก้ใน commit
`4fc42e3 fix: preserve restart exit code in recovery errors`: error = `rc=<n>: <stderr>` (stderr ว่าง -> `rc=<n>`)
ไม่กรอง warning ทิ้ง · พิสูจน์ด้วย unit test ระดับ controller -> recovery_events
(`test_ssh_warning_does_not_hide_exit_code`, `test_exit_code_reaches_recovery_events`) ·
**[decision]** ไม่ rerun 9B.5 — เป็นการแก้การแสดงผล error ใน audit ไม่ใช่ recovery logic ·
rows 4–6 ใน DB คงข้อความเดิม (บันทึกก่อนแก้)

### B6. 9B.6 Restore + กลับ HEALTHY จาก CRITICAL

**[observed]** คืน `restart_command` -> `git diff -- config/config.yaml` ว่าง ·
`START_AT_UTC=2026-09-23T16:14:24Z` (`suricata.sh start` exit 0) · `pgrep -x suricata` -> 65422 (23:14:25 +07)
```
16:14:21Z ERROR    Suricata ยังอยู่ในสถานะ CRITICAL (PROCESS_DOWN;EVE_STALE) — ...
16:14:35Z DEBUG    ได้รับ EVE stats event (uptime=10)
16:14:36Z DEBUG    health = HEALTHY (stats_age=1.6s)
16:14:36Z WARNING  Suricata กลับมา HEALTHY หลังอยู่ในสถานะ CRITICAL
16:14:45Z DEBUG    ได้รับ EVE stats event (uptime=20)
16:14:51Z DEBUG    health = HEALTHY (stats_age=6.7s)
16:14:55Z / 16:15:05Z / 16:15:15Z / 16:15:25Z  stats uptime 30 / 40 / 50 / 60
```
eve.json: 23:14:55 / 23:15:05 / 23:15:15 / 23:15:25 (+07) · ไม่มี recovery attempt ในช่วงนี้ (manual start)

**Result: PASS** — CRITICAL ไม่ค้างถาวร กลับ HEALTHY เมื่อ Suricata functional อีกครั้ง

หลังหยุด engine: `git status` -> untracked `data/` เท่านั้น · `git diff` ว่าง

### B7. ข้อจำกัด (Report — Discussion/Limitations)

- **ไม่มี delay ระหว่าง attempt เมื่อ restart command ล้มทันที:** When the restart command fails
  immediately, subsequent recovery attempts are currently issued without an inter-attempt delay.
  Therefore, all three attempts may occur within a very short interval (observed: 0.49 s, rows 4–6).
  The current FR-13 requirement specifies a maximum of three attempts but does not specify a minimum
  delay between attempts.
- **NFR-06 (audit ไม่ทำให้ recovery ล้ม):** ครอบคลุมด้วย unit test (`test_audit_failure_does_not_break_recovery`)
  ไม่ได้ inject ความล้มเหลวของ DB ใน lab
- `data/experiment.db-wal` / `-shm` ค้างจากการหยุด engine ด้วย TaskStop (ไม่ได้ checkpoint) — ไม่แตะ ไม่ commit

## หมายเหตุ: verify_stream_stats.py

scratch script (ไม่อยู่ใน repo) เรียก `stream_events(host, eve_path, on_stats=cb)` ของจริง
และมี watchdog terminate ssh subprocess ที่ 35 s — เพราะ `next(stream)` block ถ้าไม่มี alert
(stats ไม่ถูก yield) · `ssh returncode: [1]` มาจากการ terminate ของ watchdog ตามแผน
**[interpretation]** ยังไม่ได้ตรวจแยกว่า returncode 1 มีสาเหตุอื่นร่วมหรือไม่
