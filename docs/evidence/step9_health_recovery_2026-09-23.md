# STEP 9 — Health / Recovery Lab Validation (FR-12 / FR-13)

วันที่: 2026-09-23 · ขอบเขต: infrastructure readiness ก่อน T1–T11 — **ไม่ใช่ผลการทดลอง**

ป้ายกำกับ: **[observed]** = วัด/อ่านได้จริง · **[config]** = ค่าที่ตั้งไว้ ·
**[decision]** = ข้อตัดสินใจของผู้วิจัย · **[interpretation]** = การตีความ

สถานะ: ส่วน A (stats path + persistence) **เสร็จ** · ส่วน B (HealthMonitor / recovery runtime) **ยังไม่รัน**

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

## B. HealthMonitor / Recovery runtime — ยังไม่รัน

- 9.1 HEALTHY (process + fresh stats) / DEGRADED (process หยุด หรือ stats ค้าง > 30 s)
- 9.2 DEGRADED -> `/usr/local/etc/rc.d/suricata.sh restart` -> functional check -> HEALTHY
- 9.3 recovery ล้ม ×3 -> CRITICAL · ไม่มี attempt 4 · `recovery_events` ครบทุก attempt
- 9.4 CRITICAL latch

**[config]** `health.restart_command` ใน `config/config.yaml` ยังเป็น `""` — ต้องตั้งเป็นคำสั่งที่พิสูจน์แล้ว
(A3) ก่อนทดสอบ 9.2

## หมายเหตุ: verify_stream_stats.py

scratch script (ไม่อยู่ใน repo) เรียก `stream_events(host, eve_path, on_stats=cb)` ของจริง
และมี watchdog terminate ssh subprocess ที่ 35 s — เพราะ `next(stream)` block ถ้าไม่มี alert
(stats ไม่ถูก yield) · `ssh returncode: [1]` มาจากการ terminate ของ watchdog ตามแผน
**[interpretation]** ยังไม่ได้ตรวจแยกว่า returncode 1 มีสาเหตุอื่นร่วมหรือไม่
