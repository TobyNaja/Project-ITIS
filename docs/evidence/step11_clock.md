# STEP 11 — Clock observations (§1.1)

ค่าบวกของ `w32tm /stripchart /computer:192.168.227.150` = SEC01 ช้ากว่า pfSense
ค่าในไฟล์นี้เป็น **contextual observation** ไม่ได้ใช้ชดเชย timestamp ใด ๆ

## Clock synchronization observation

SEC01–pfSense clock offset could not be reduced to near-zero despite `w32tm /resync` attempts.

No timestamp compensation was applied.

Primary experiment uses controlled EVE injection, with `t_event` generated on SEC01; therefore
M1/M4 are interpreted as SEC01-local EVE ingestion/end-to-end latency measurements.

Clock offset is retained as contextual limitation only.

## ค่าที่วัดได้

| ชุด | จุด | เวลา (+07) | resync | offset min / max / mean (ms) |
|---|---|---|---|---|
| DRYRUN-T4 รอบ 2 | before | 2026-09-24 22:04:01 | สำเร็จ (Last Sync 22:03:56) | +157.86 / +158.96 / +158.00 |
| T1 | before | 2026-09-24 22:15:17 | สำเร็จ (Last Sync 22:15:17) | +169.21 / +169.39 / +169.32 |
| T1 | after | 2026-09-24 22:30:47 | — | +186.29 / +186.40 / +186.35 |
| T2–T8 | after | — | — | **ไม่ได้วัด** (ชุดวันที่ 1 จบ ~00:21 +07 แล้วปิดเครื่อง) |
| วันที่ 2 (T9–T11) | before | 2026-09-25 20:49:15 | **ไม่ได้ resync** — `w32tm /resync` จาก shell ที่ไม่ใช่ admin = Access is denied (0x80070005); Last Successful Sync 19:57:42 (sync อัตโนมัติหลังบูต) | +183.70 / +183.98 / +183.87 |
| วันที่ 2 (T9–T11) | after | 2026-09-25 21:29:49 | — | +162.30 / +163.30 / +162.58 |

- `w32tm /query /status` ทุกครั้ง: Source `time.windows.com`, Stratum 5, Root Dispersion ≈ 7.9 s
- pfSense เพิ่ง boot (~21:55 +07) ก่อน DRYRUN2 — ครั้งแรกที่วัด (21:50) stripchart `0x800705B4`
  (timeout) เพราะ pfSense node ใน GNS3 ยังไม่ได้เปิด ไม่ใช่ค่า offset
- drift ระหว่างชุด T1: +17.0 ms ใน 15.5 นาที ≈ 1.1 ms/นาที (ตรงกับที่สังเกตก่อน freeze)

- ชุด T2–T8 ไม่มี offset_after: ไม่ได้รัน stripchart ท้ายชุดก่อนปิดเครื่อง (2026-09-25 ~00:21 +07)
- วันที่ 2: pfSense boot ~20:46 +07 (uptime 3 นาทีตอน 20:49) · Suricata PID 86127 · stats uptime 150 s ตอน 20:49:13
- ต้นชุดวันที่ 2 ไม่ได้ resync ตาม §1.1 (ไม่มีสิทธิ์ admin) — offset ใช้เป็น contextual observation เท่านั้นเหมือนเดิม
- วันที่ 2 ระหว่างชุด (20:49 -> 21:29, ไม่มี resync): offset ลดลง −21.3 ms ใน ~40 นาที — ทิศตรงข้ามกับ drift ของวันแรก (+1.1 ms/นาที) · บันทึกตามจริง ไม่ได้หาสาเหตุ
