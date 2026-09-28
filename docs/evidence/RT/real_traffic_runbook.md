# Runbook — Real-Traffic Tests RT-1 ถึง RT-3 (supplementary functional validation)

> แต่ละ test รันครั้งเดียว และพิสูจน์คนละ behavior — **ไม่ใช่การวัดเชิงสถิติ** และไม่แตะ dataset ของ STEP 11
> (`data/step11_experiment.db` sha256 `d4ffe244…` ห้ามถูกเขียน)

> **สถานะ: รันแล้ว 2026-09-28 05:52–06:23 UTC** — ลำดับที่ทำจริงคือ RT-1 (3 ครั้ง) → RT-2 → RT-3 ผลตรงกับที่คาดทุก Test
> ผลดิบจาก DB และ log อยู่ใน `rt_results_raw.txt` · ภาพประกอบอยู่ในรายงานแล็บ (หัวข้อ 4.6) ไม่ได้เก็บใน repository
> ระหว่าง RT พบ SSH timeout 1 ครั้ง (06:06:23Z) สาเหตุคือ ssh ของ Windows ได้ stdin เป็น Console → ให้รัน Engine ด้วย `< NUL` (ดู README)

| Test | Traffic จาก Kali | สิ่งที่คาดหวัง (อิง `config/rules.yaml`) | สิ่งที่พิสูจน์ |
|---|---|---|---|
| RT-1 | SYN ×10 → :22 | RULE-001 → BLOCK → traffic ถูก drop → 300 s → auto-UNBLOCK → traffic กลับมา | End-to-end + lifecycle (FR-09/10/11) |
| RT-2 | SYN ×4 → :22 | ไม่เกิด correlated pattern (4 < `min_events: 5`) → ไม่ BLOCK | Threshold / Correlation (FR-03) |
| RT-3 | SYN ×10 + Kali อยู่ใน allowlist | RULE-003 (priority 1) → NO_AUTO_BLOCK → ไม่ BLOCK | Allowlist safety |

**ลำดับที่ใช้:** Preflight → RT-2 → RT-1 → RT-3 → Cleanup
(RT-2 ไม่ทิ้ง state ค้าง · RT-1 จบด้วย unblock เอง · RT-3 ต้องแก้ allowlist และ restart engine จึงไว้ท้ายสุด)

**ค่าที่ใช้** (ตรวจกับ lab แล้ว ดู memory lab-facts)
- Kali `192.168.2.10` → pfSense em2 `192.168.2.1` · pfSense SSH `admin@192.168.227.150`
- EVE `/var/log/suricata/suricata_em224404/eve.json` · pf table `ITIS_BLOCK_TEST`
- Suricata rule ทดสอบ (ยังค้างอยู่บน pfSense): `alert tcp any any -> any 22 (msg:"ITIS TEST SSH SYN"; flags:S; priority:1; sid:1000101; rev:1;)`
  → ICMP **ไม่มี rule** แล้ว ping จึงไม่สร้าง event → ใช้ ping ตรวจว่า traffic ผ่าน/ไม่ผ่าน ได้โดยไม่รบกวนผล
- DB ของรอบนี้: `data/supp_rt.db` (ใหม่ · ห้ามใช้ `supp_demo*.db` / `supp_real_traffic*.db` ซ้ำ)

**ภาพประกอบ:** ใช้ในรายงานแล็บหัวข้อ 4.6 จำนวน 16 ภาพ (รูปที่ 33–48)

**กติกาการแคปภาพ:** ทุกภาพบน Kali ต้องมีเวลา UTC ติดอยู่ในภาพ → ให้ขึ้นต้นทุกคำสั่งด้วย `date -u +%FT%TZ;`
ตั้งชื่อไฟล์ภาพเป็น `RT<n>_<ลำดับ>_<อะไร>.png` แล้วเก็บไว้ใน `docs/evidence/RT/img/`

---

## ขั้น 0 — Preflight (ห้ามข้าม: attempt 2 ล้มเพราะขั้นนี้)

**สิ่งที่รู้จากรอบก่อน**
- 26 ก.ย. `supp_real_traffic.db`: lifecycle ครบ (BLOCK 14:27:52Z → UNBLOCK 14:32:53Z VERIFIED) **แต่** มี
  `recovery_events` PROCESS_DOWN ตอน 14:27:01Z หมายความว่า health check (`pgrep` ผ่าน SSH) เคยล้มจนทำให้ Suricata ถูก restart
- 27 ก.ย. attempt 2: SSH `pgrep` timeout ตอน 09:36:14Z → stream หลุด → engine หยุดทั้งระบบ (ในโค้ดไม่มี reconnect)
- สิ่งที่สงสัยคือ sshguard หรือ SSH ของ pfSense ไม่ตอบชั่วคราว **ยังไม่ได้พิสูจน์** จึงต้องตรวจด้วยขั้น 0.3

### 0.1 เปิด lab
GNS3 → start node pfSense และ Kali → รอ pfSense บูตเสร็จประมาณ 2–3 นาที

### 0.1b แคปภาพ rule
pfSense GUI: Services > Suricata > em2 > Rules > custom.rules → `RT0_rule.png` (ต้องเห็น sid 1000101)

### 0.2 ตรวจ pfSense (PowerShell หรือ Git Bash บน Windows)
```bash
ssh -T -o BatchMode=yes admin@192.168.227.150 "date -u; pgrep -x suricata; pfctl -t ITIS_BLOCK_TEST -T show; echo ---sshguard; pfctl -t sshguard -T show; echo ---rule; grep -rh 'sid:1000' /usr/local/etc/suricata/*/rules/custom.rules"
```
ต้องได้ผลดังนี้: มี PID ของ Suricata · `ITIS_BLOCK_TEST` **ว่าง** · sshguard **ไม่มี** `192.168.227.1` · rule มีแค่ sid 1000101
- ถ้า `192.168.227.1` อยู่ใน sshguard ให้ลบออกก่อนด้วย `pfctl -t sshguard -T delete 192.168.227.1` แล้วเพิ่ม
  `192.168.227.1` ใน **System > Advanced > Admin Access > Login Protection > Pass list** จากนั้นแจ้ง Claude เพราะต้องบันทึกเป็นข้อค้นพบ

### 0.3 นาฬิกา (บันทึกค่าไว้ใส่รายงาน)
```powershell
w32tm /stripchart /computer:192.168.227.150 /samples:5 /dataonly
```

### 0.4 ชี้ config ไปที่ DB ใหม่
แก้ `config/config.yaml` บรรทัด `db_path: "data/supp_demo.db"` ให้เป็น `db_path: "data/supp_rt.db"`
ตรวจว่า `config/allowlist.yaml` ยังเป็น `allowlist: []`

### 0.5 Start engine (PowerShell · หน้าต่างที่ 1 เปิดทิ้งไว้ตลอดการทดสอบ)
```powershell
$env:ITIS_PFSENSE_HOST = "admin@192.168.227.150"
$env:ITIS_EVE_PATH     = "/var/log/suricata/suricata_em224404/eve.json"
.\.venv\Scripts\python.exe run_phase4.py
```
หน้าต่างที่ 2 ใช้ดู log:
```powershell
Get-Content logs\engine.log -Wait -Tail 20
```
ต้องเห็นบรรทัด `เริ่มอ่าน EVE จาก admin@192.168.227.150:/var/log/suricata/suricata_em224404/eve.json` (path ต้องขึ้นต้นด้วย `/var` ห้ามเป็น `C:/...`)

### 0.6 Soak test: ปล่อย engine ว่าง ๆ 6 นาที (ยาวกว่าหน้าต่าง 300 s ของ RT-1)
ระหว่างนี้**ห้ามยิงอะไรจาก Kali** · ครบ 6 นาทีแล้วให้ Claude รัน:
```bash
.venv/Scripts/python.exe docs/evidence/RT/rt_check.py data/supp_rt.db
```
- **ผ่าน** เมื่อ `recovery_events` = 0 และใน log ไม่มี `SSH timeout` / `ssh ล้มเหลว` → ไปต่อ RT-2 ได้
- **ไม่ผ่าน** → หยุดทันที ห้ามยิง test เพราะผล RT-1 จะเชื่อไม่ได้ · เก็บ log และรันบน pfSense
  `grep -i sshguard /var/log/auth.log | tail -20` แล้วส่งให้ Claude วิเคราะห์ก่อน

---

## RT-2 — SYN ×4 (ต่ำกว่าเกณฑ์)

**ก่อนเริ่ม:** Kali ต้องไม่ส่ง SYN ไป :22 มาแล้ว **≥ 30 s** (window 10 s + cooldown 10 s + เผื่อ)
**ห้ามใช้ `nc` ใน RT-2** เพราะ nc ส่ง SYN ไป :22 ซึ่งจะนับเป็น event ที่ 5 ทันที

| # | ทำอะไร (Kali) | 📸 แคป |
|---|---|---|
| 1 | `date -u +%FT%TZ; sudo hping3 -S -p 22 -c 4 -i u500000 192.168.2.1` | `RT2_1_hping4.png` — ต้องเห็น `4 packets transmitted` |
| 2 | รอ 15 s แล้วบอก Claude "เช็ค RT-2 since <เวลาจากข้อ 1>" | Claude แคป output ของ rt_check → `RT2_2_db.png` |
| 3 | `date -u +%FT%TZ; ping -c 4 192.168.2.1` | `RT2_3_ping.png` — 0% loss |
| 4 | pfSense GUI: **Diagnostics > Tables > ITIS_BLOCK_TEST** | `RT2_4_table.png` — ว่าง |

**ผ่าน เมื่อ:** security_events = 4 · correlated_patterns = 0 · decisions = 0 · actions = 0 · table ว่าง · ping 0% loss
(ภาพ "Engine ไม่ BLOCK" ให้ใช้ผลจาก DB เพราะ log มีแค่ `raw event …` 4 บรรทัด ซึ่งพิสูจน์ได้อ่อนกว่า)

---

## RT-1 — SYN ×10 → BLOCK → 300 s → auto-UNBLOCK

**ก่อนเริ่ม:** เว้นจาก RT-2 ≥ 30 s

| # | เวลา | ทำอะไร | 📸 แคป |
|---|---|---|---|
| 1 | ก่อนยิง | Kali: `date -u +%FT%TZ; ping -c 3 192.168.2.1; nc -zv -w2 192.168.2.1 22` | `RT1_1_before.png` — ping ผ่าน · nc `open` |
| 2 | ก่อนยิง | GUI: Diagnostics > Tables > ITIS_BLOCK_TEST | `RT1_2_table_empty.png` |
| 3 | **T0** | ⚠️ ข้อ 1 เพิ่งส่ง SYN ไป 1 ครั้ง → **รอ ≥ 30 s** แล้ว Kali: `date -u +%FT%TZ; sudo hping3 -S -p 22 -c 10 -i u500000 192.168.2.1` | `RT1_3_hping10.png` — ช่วงต้นควรเห็น SA แล้ว reply หายไปกลางทาง |
| 4a | T0+~5 s | pfSense GUI: Services > Suricata > **Alerts** (em2) | `RT1_4_suricata.png` — Alert sid 1000101 จาก 192.168.2.10 หลายแถว |
| 4b | T0+~5 s | log หน้าต่างที่ 2 | `RT1_5_log.png` — `raw event … sid=1000101` ติดกันหลายบรรทัด |
| 5 | T0+~10 s | บอก Claude "เช็ค RT-1 since T0" | `RT1_6_db_block.png` — pattern 5 events → risk → **RULE-001 BLOCK** → action BLOCK SUCCESS/VERIFIED · จด `expires_at` |
| 6 | ทันที | GUI: Diagnostics > Tables > ITIS_BLOCK_TEST | `RT1_7_table_blocked.png` — มี `192.168.2.10` |
| 7 | ระหว่าง block | Kali: `date -u +%FT%TZ; ping -c 5 192.168.2.1; nc -zv -w2 192.168.2.1 22` | `RT1_8_during.png` — ping **100% loss** · nc **timed out** |
| 8 | ระหว่าง block | (ถ้าทำได้) GUI: Firewall > Rules > em2 → rule `block … <ITIS_BLOCK_TEST>` มีตัวนับขึ้น | `RT1_9_rule_counter.png` (ภาพ Firewall Rules ที่ยังค้างอยู่ในรายงาน) |
| 9 | รอ | **ห้ามปิด engine / ห้ามยิงอะไร** จนเลย `expires_at` + 10 s (runner เช็คทุก 1 s) | — |
| 10 | หลัง expires | บอก Claude "เช็ค RT-1 unblock" | `RT1_10_db_unblock.png` — action UNBLOCK SUCCESS/VERIFIED ห่างจาก BLOCK ≈ 300 s · active_blocks = EXPIRED |
| 11 | หลัง expires | GUI: Diagnostics > Tables > ITIS_BLOCK_TEST | `RT1_11_table_empty.png` — ว่าง |
| 12 | หลัง expires | Kali: `date -u +%FT%TZ; ping -c 3 192.168.2.1; nc -zv -w2 192.168.2.1 22` | `RT1_12_after.png` — ping ผ่าน · nc `open` |

**สิ่งที่คาดไว้ล่วงหน้า (ไม่ใช่ความผิดปกติ)**
- SYN ใน hping3 ที่ตามหลังมาและ SYN จาก `nc` ในข้อ 7 ยังถูก Suricata จับได้ (Suricata เห็นแพ็กเก็ตก่อน pf drop) → ถ้าครบ 5 events ใน 10 s
  จะเห็น log `duplicate pattern ระหว่างที่ 192.168.2.10 ถูก block อยู่` = FR-11 ไม่ block ซ้ำ ซึ่งเป็นพฤติกรรมที่ถูกต้อง ใช้เป็นหลักฐานเพิ่มได้
- ในข้อ 3 จำนวน SA ที่ได้รับจะน้อยกว่า 10 เพราะ block เริ่มทำงานหลัง event ที่ 5 (รอบก่อนได้ 6/10)

**ผ่าน เมื่อ:** BLOCK VERIFIED · traffic ข้อ 7 ล้มทั้งคู่ · UNBLOCK เกิดจาก **timer ระหว่างรัน** (ไม่ใช่ startup reconcile) · traffic ข้อ 12 กลับมา
**ถ้า engine หลุดระหว่างรอ** (log หยุด/SSH error): ห้าม restart engine ทันที ให้แคป log และ `pfctl -t ITIS_BLOCK_TEST -T show` ก่อน แล้วแจ้ง Claude ·
ห้ามเขียน RT-1 ว่าผ่าน

---

## RT-3 — SYN ×10 + Allowlist

**เตรียม:** เว้นจาก RT-1 ≥ 30 s และ table ต้องว่าง

| # | ทำอะไร | 📸 แคป |
|---|---|---|
| 1 | หน้าต่างที่ 1: **Ctrl+C** หยุด engine | — |
| 2 | แก้ `config/allowlist.yaml` ให้เป็น<br>`allowlist:`<br>`  - "192.168.2.10"` | `RT3_1_allowlist.png` — ไฟล์ใน editor |
| 3 | Start engine ใหม่ด้วยคำสั่งเดียวกับขั้น 0.5 (DB เดิม `supp_rt.db`) · รอเห็นบรรทัด `เริ่มอ่าน EVE จาก …` | — |
| 4 | Kali: `date -u +%FT%TZ; sudo hping3 -S -p 22 -c 10 -i u500000 192.168.2.1` | `RT3_2_hping10.png` — ได้ SA ครบ 10 (ไม่ถูก drop) |
| 5 | รอ 10 s แล้วบอก Claude "เช็ค RT-3 since <เวลาข้อ 4>" | `RT3_3_db.png` — decision **RULE-003 NO_AUTO_BLOCK allowlisted=1** · actions มีแค่ `ALERT` · **ไม่มี BLOCK** · risk score ยังถูกคำนวณ (factor C = 0) |
| 6 | GUI: Diagnostics > Tables > ITIS_BLOCK_TEST | `RT3_4_table.png` — ไม่มี `192.168.2.10` |
| 7 | Kali: `date -u +%FT%TZ; ping -c 4 192.168.2.1` | `RT3_5_ping.png` — 0% loss |

**ผ่าน เมื่อ:** มี pattern ≥ 5 events · decision = NO_AUTO_BLOCK โดย RULE-003 · ไม่มี action BLOCK · table ว่าง · ping ผ่าน

---

## ขั้น 9 — Cleanup (ทำให้ครบทุกข้อ แล้วติ๊กทีละข้อ)

- [ ] หน้าต่างที่ 1: **Ctrl+C** หยุด engine
- [ ] Claude: checkpoint `data/supp_rt.db` (`PRAGMA wal_checkpoint(TRUNCATE)`) แล้วรัน rt_check ทั้ง DB เก็บเป็น `docs/evidence/RT/rt_check_full.txt`
- [ ] `git checkout config/config.yaml config/allowlist.yaml` แล้ว `git status` ต้องไม่มี `M config/…`
- [ ] pfSense GUI: Services > Suricata > em2 > Rules > custom.rules → ลบ sid 1000101 แล้วใส่คืน
      `alert icmp any any -> any any (msg:"D"; flow:stateless; sid:1000001; rev:2;)` → Save
- [ ] Restart Suricata: `ssh -T -o BatchMode=yes admin@192.168.227.150 "pgrep -x suricata; /usr/local/etc/rc.d/suricata.sh restart; sleep 8; pgrep -x suricata"` → **PID ต้องเปลี่ยน**
- [ ] `pfctl -t ITIS_BLOCK_TEST -T show` → ว่าง
- [ ] `sha256sum data/step11_experiment.db` → ต้องขึ้นต้นด้วย `d4ffe244`
- [ ] ย้ายภาพทั้งหมดไป `docs/evidence/RT/img/` แล้วบอก Claude "RT เสร็จ" เพื่อเขียน `docs/evidence/RT/results.md` และแก้บท 4.6 ของรายงานแล็บ
      (ตาราง Expected / Observed / ผล / รูป · เก็บ attempt 1–2 ไว้เป็นประวัติ ไม่ลบ)
