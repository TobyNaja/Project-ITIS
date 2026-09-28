# Runbook — Real-Traffic Tests RT-4 และ RT-5

> ต่อจาก RT-1 ถึง RT-3 (`real_traffic_runbook.md`) · แต่ละ Test ทำครั้งเดียว เป็นการยืนยันการทำงาน ไม่ใช่การวัดเชิงสถิติ
> ห้ามแตะ `data/step11_experiment.db` (sha256 `d4ffe244…`) · ฐานข้อมูลของรอบนี้ = `data/supp_rt2.db`

> **สถานะ: รันแล้ว 2026-09-28 10:00–10:10 UTC** — RT-5 ได้ RULE-002 / ALERT (69.5 HIGH) ไม่ Block · RT-4 กู้คืนสำเร็จครั้งที่ 1 ภายใน 15 วินาที (PID 29747 → 2365)
> ผลดิบอยู่ใน `rt4_rt5_results_raw.txt` · ภาพประกอบอยู่ในรายงานหัวข้อ 5.6.4–5.6.5 (รูปที่ 49–64)
> ต่างจากแผน: ไม่ได้เปิด Engine ทิ้งไว้ 5 นาทีก่อนเริ่ม และไม่ได้รันด้วย `< NUL` จึงมี restart ที่ไม่จำเป็น 2 ครั้งหลัง RT-4 (recovery_events แถว 2–3)
> ขั้นที่ 3.3 (คืน Suricata rule) **ไม่ได้ทำตามการตัดสินใจของผู้ใช้** — custom.rules บน pfSense ยังเป็น sid 1000101 + 1000102

| Test | ทำอะไร | ผลที่คาด (อิงโค้ดและ `config/rules.yaml`) | คู่กับ |
|---|---|---|---|
| RT-5 | Kali ส่ง TCP SYN × 5 ไปพอร์ต **23** (Rule ใหม่ sid 1000102, priority 2 = MEDIUM) | Pattern 5 Event · Risk 69.5 (HIGH) · **RULE-002 → ALERT** · action `ALERT / NOT_APPLICABLE` · ไม่แตะ pfSense · ping ผ่าน | T3 |
| RT-4 | หยุด Suricata บน pfSense ระหว่างที่ Engine ทำงาน | ภายใน ~15 วินาที `DEGRADED (PROCESS_DOWN)` → restart attempt 1/3 → `HEALTHY` · `recovery_events` 1 แถว `SUCCESS` · Suricata PID ใหม่ · หลังกู้คืนยังตรวจจับได้ต่อ | T8 |

**ลำดับ:** Preflight → RT-5 → RT-4 → Cleanup
(RT-5 ต้องใช้ Suricata ที่โหลด Rule ใหม่แล้ว · RT-4 ทำ Suricata restart จึงไว้ท้าย)

**ทำไม RT-5 ใช้พอร์ต 23:** Rule เดิม sid 1000101 (SYN → 22) เป็น priority 1 = HIGH ถ้า Kali ยิงพอร์ต 22 ใน Window เดียวกัน
Pattern จะมี max_severity = 1 แล้วกลายเป็น RULE-001 BLOCK ทันที ดังนั้นระหว่าง RT-5 **ห้ามใช้ `nc … 22`**

**ค่าที่ใช้**
- Kali `192.168.2.10` → pfSense em2 `192.168.2.1` · pfSense SSH `admin@192.168.227.150`
- pf table `ITIS_BLOCK_TEST` · restart `/usr/local/etc/rc.d/suricata.sh restart`
- รัน Engine ด้วย `< NUL` เสมอ (กัน SSH ค้างจน restart Suricata โดยไม่จำเป็น — สำคัญมากกับ RT-4 เพราะต้องแยกให้ออกว่า restart มาจาก fault จริง)

**กติกาการแคปภาพ:** ทุกภาพต้องมีเวลา UTC
- Kali: ขึ้นต้นคำสั่งด้วย `date -u ;`
- PowerShell: `(Get-Date).ToUniversalTime().ToString("HH:mm:ss")`

---

## ขั้นที่ 0 — Preflight (~10 นาที)

| # | ใคร | ทำอะไร | ต้องเห็น |
|---|---|---|---|
| 0.1 | ผู้ใช้ | เปิด GNS3 → start pfSense และ Kali | Kali ping 192.168.2.1 ได้ |
| 0.2 | ผู้ใช้ | ตรวจว่า Engine ไม่ได้รันค้าง | ไม่มีหน้าต่าง `run_phase4.py` |
| 0.3 | ผู้ใช้ | pfSense GUI: **Services > Suricata > (em2) Edit > Rules > custom.rules** เพิ่มบรรทัดที่สอง (คงบรรทัด sid 1000101 ไว้)<br>`alert tcp any any -> any 23 (msg:"ITIS TEST TELNET SYN MEDIUM"; flags:S; priority:2; sid:1000102; rev:1;)`<br>กด **Save** | 📸 **RT5-0** หน้า custom.rules ที่เห็นทั้ง 2 บรรทัด |
| 0.4 | ผู้ใช้ | Save ใน GUI **ไม่ได้** restart Suricata → สั่ง restart (GUI ปุ่ม restart ที่ Interfaces หรือ SSH `/usr/local/etc/rc.d/suricata.sh restart`) | Suricata กลับมาทำงาน |
| 0.5 | Claude | ตรวจแบบ read-only: custom.rules มี 1000101 + 1000102 · PID ของ Suricata เปลี่ยน · rules โหลดไม่ error · pf table ว่าง | ผ่านทั้งหมด |
| 0.6 | Claude | แก้ `config/config.yaml` → `db_path: "data/supp_rt2.db"` · ตรวจ `allowlist: []` | `git diff` เห็นแค่บรรทัด db_path |
| 0.7 | ผู้ใช้ | PowerShell (ที่ root ของโปรเจกต์):<br>`cmd /c ".venv\Scripts\python.exe run_phase4.py < NUL"` | บรรทัด `เริ่มอ่าน EVE จาก admin@192.168.227.150:/var/log/suricata/suricata_em224404/eve.json` |
| 0.8 | Claude | ตรวจว่า Engine รันผ่าน `cmd` (มี `< NUL`) และเปิดทิ้งไว้ **5 นาที** | `recovery_events` = 0 แถว และไม่มี `SSH timeout` ใน log |

> ถ้าข้อ 0.8 พบ SSH timeout / recovery ที่ไม่ได้สั่ง → **หยุด** แจ้ง Claude ก่อนทำ RT-4

---

## ขั้นที่ 1 — RT-5: Alert ระดับ MEDIUM ต้องได้ ALERT ไม่ Block

| # | ที่ | คำสั่ง / การกระทำ | ต้องเห็น | ภาพ |
|---|---|---|---|---|
| 1.1 | Kali | `date -u ; ping -c 3 192.168.2.1` | 0% packet loss | 📸 **RT5-1** |
| 1.2 | Kali | `date -u ; sudo hping3 -S -p 23 -c 5 -i u500000 192.168.2.1` | `5 packets transmitted` | 📸 **RT5-2** |
| 1.3 | Engine | ดูหน้าต่าง Engine | 4 บรรทัด `matched=False` แล้ว `matched=True decision=ALERT` | 📸 **RT5-3** |
| 1.4 | PS2 | `.\.venv\Scripts\python.exe docs\evidence\RT\rt_check.py data\supp_rt2.db` | events 5 (signature_id **1000102**, severity **2**) · pattern 5 · risk **69.5 HIGH** · **RULE-002 / ALERT** · action `ALERT / NOT_APPLICABLE` · active_blocks 0 | 📸 **RT5-4** |
| 1.5 | pfSense | Diagnostics > Tables > ITIS_BLOCK_TEST | ว่าง | 📸 **RT5-5** |
| 1.6 | Kali | `date -u ; ping -c 4 192.168.2.1` | 0% packet loss | 📸 **RT5-6** |
| 1.7 | ผู้ใช้ | บอก Claude "RT-5 เสร็จ" | Claude ตรวจ DB | — |

> ถ้า pattern ไม่เกิด (event < 5 เพราะแพ็กเก็ตหาย) → รอ 30 วินาทีแล้วยิง 1.2 ซ้ำ และบันทึกว่าเป็นครั้งที่ 2
> RT-5 ใช้แค่ ping ตรวจทราฟฟิก (ไม่ใช้ nc 22 — ดูเหตุผลด้านบน)

รอ **อย่างน้อย 30 วินาที** ก่อนเริ่ม RT-4

---

## ขั้นที่ 2 — RT-4: Suricata หยุด ระบบต้องกู้คืนเอง

| # | ที่ | คำสั่ง / การกระทำ | ต้องเห็น | ภาพ |
|---|---|---|---|---|
| 2.1 | PS2 | `ssh admin@192.168.227.150 "pgrep -x suricata"` | PID เดิม (จดไว้) | 📸 **RT4-1** |
| 2.2 | PS2 | `(Get-Date).ToUniversalTime().ToString("HH:mm:ss"); ssh admin@192.168.227.150 "/usr/local/etc/rc.d/suricata.sh stop"` | เวลา t_fault + ข้อความหยุด Suricata | 📸 **RT4-2** |
| 2.3 | PS2 | ทันทีหลัง 2.2: `ssh admin@192.168.227.150 'pgrep -x suricata; echo rc=$?'` | ไม่มี PID · `rc=1` (Suricata หยุดจริง) | 📸 **RT4-3** |
| 2.4 | Engine | รอ ~15–40 วินาที ดูหน้าต่าง Engine | `Suricata health = DEGRADED (PROCESS_DOWN …)` → `เริ่ม recovery Suricata attempt 1/3` → `สั่ง restart Suricata …` → `recovery Suricata สำเร็จที่ attempt 1/3` | 📸 **RT4-4** |
| 2.5 | PS2 | `ssh admin@192.168.227.150 "pgrep -x suricata"` | **PID ใหม่** (ต่างจาก 2.1) | 📸 **RT4-5** |
| 2.6 | pfSense | Services > Suricata > Interfaces | em2 สถานะทำงาน (ไอคอนเขียว) | 📸 **RT4-6** |
| 2.7 | PS2 | `.\.venv\Scripts\python.exe docs\evidence\RT\rt_check.py data\supp_rt2.db` | `recovery_events` 1 แถว: `PROCESS_DOWN · attempt=1 · result=SUCCESS` | 📸 **RT4-7** |
| 2.8 | Kali | รอให้ 2.4 สำเร็จก่อน แล้ว `date -u ; sudo hping3 -S -p 22 -c 4 -i u500000 192.168.2.1` | `4 packets transmitted` | 📸 **RT4-8** |
| 2.9 | PS2 | rt_check ซ้ำ | security_events เพิ่ม 4 แถว (sid 1000101) ไม่มี pattern ใหม่ = **Suricata ตรวจจับได้ต่อหลังกู้คืน** และ Engine ยังรับ Event อยู่ | 📸 **RT4-9** |
| 2.10 | ผู้ใช้ | บอก Claude "RT-4 เสร็จ" | Claude ตรวจ log + DB | — |

> 2.8 ใช้ SYN × 4 (ต่ำกว่าเกณฑ์) เพื่อพิสูจน์ว่าตรวจจับได้ต่อ โดยไม่ทำให้เกิด Block
> ถ้าผ่านไป 60 วินาทีแล้ว Engine ยังไม่ขึ้น DEGRADED หรือ recovery ล้ม → **อย่าแก้เอง** แจ้ง Claude และถ้าจำเป็นให้สั่ง
> `ssh admin@192.168.227.150 "/usr/local/etc/rc.d/suricata.sh start"` เพื่อให้ lab กลับมาก่อน

---

## ขั้นที่ 3 — Cleanup (ต้องทำครบ)

| # | ใคร | ทำอะไร |
|---|---|---|
| 3.1 | ผู้ใช้ | หยุด Engine (Ctrl+C) |
| 3.2 | Claude | checkpoint `data/supp_rt2.db` · `git checkout config/config.yaml` · ตรวจ hash `step11_experiment.db` = `d4ffe244…` · บันทึกผลดิบลง `docs/evidence/RT/rt4_rt5_results_raw.txt` |
| 3.3 | ผู้ใช้ | pfSense custom.rules: **ลบ** 1000101 และ 1000102 · **ใส่คืน** `alert icmp any any -> any any (msg:"D"; flow:stateless; sid:1000001; rev:2;)` · Save · restart Suricata |
| 3.4 | Claude | ตรวจแบบ read-only ว่า custom.rules เหลือแค่ ICMP 1000001 · Suricata PID เปลี่ยน · pf table ว่าง |
| 3.5 | Claude | เขียนผล RT-4 / RT-5 ลงเล่ม `ITIS_final_report.docx` (หัวข้อ 5.6) พร้อมกล่องรูปให้แปะ |

---

## รายการภาพ (16 ภาพ)

| ภาพ | แคปอะไร |
|---|---|
| RT5-0 | custom.rules มี sid 1000101 และ 1000102 |
| RT5-1 | Kali ping ก่อนยิง (0% loss) |
| RT5-2 | Kali hping3 SYN × 5 ไปพอร์ต 23 |
| RT5-3 | Engine log `matched=True decision=ALERT` |
| RT5-4 | rt_check: severity 2 · RULE-002 · ALERT / NOT_APPLICABLE · ไม่มี Block |
| RT5-5 | pf Table ว่าง |
| RT5-6 | Kali ping หลังยิง (0% loss) |
| RT4-1 | PID ของ Suricata ก่อนหยุด |
| RT4-2 | คำสั่งหยุด Suricata พร้อมเวลา UTC |
| RT4-3 | pgrep ไม่พบ Suricata (rc=1) |
| RT4-4 | Engine log: DEGRADED → restart → recovery สำเร็จ |
| RT4-5 | PID ใหม่ของ Suricata |
| RT4-6 | pfSense Services > Suricata สถานะทำงาน |
| RT4-7 | rt_check: recovery_events SUCCESS |
| RT4-8 / RT4-9 | หลังกู้คืน: hping3 SYN × 4 และ security_events เพิ่ม 4 แถว |
