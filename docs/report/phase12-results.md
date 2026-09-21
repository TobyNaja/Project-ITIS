# บทที่ 4 ผลการทดลอง (Phase 12)

> ตัวเลขทั้งหมดในบทนี้มาจาก `docs/evidence/P12-ANALYSIS/latency_summary.json`
> ซึ่งคำนวณจาก `docs/evidence/P12-ENFORCEMENT/traces_enf.jsonl` (120 records)
> reproduce ได้ด้วย:
> ```
> python -m analysis.analyze docs/evidence/P12-ENFORCEMENT/traces_enf.jsonl --out docs/evidence/P12-ANALYSIS
> python -m analysis.plots   docs/evidence/P12-ENFORCEMENT/traces_enf.jsonl --out docs/evidence/P12-ANALYSIS
> ```

## 4.1 รูปแบบการทดลอง (Experimental Setup)

การทดลองนี้เป็น **Mode B: Synthetic EVE + Real pfSense Enforcement** กล่าวคือ
เหตุการณ์นำเข้า (EVE event) ถูกสร้างขึ้นแบบสังเคราะห์และป้อนเข้า pipeline โดยตรง
ในขณะที่ขั้นตอนบังคับใช้นโยบาย (enforcement) กระทำกับ pfSense เครื่องจริงผ่าน SSH

| รายการ | ค่า |
|---|---|
| โหมด | enforcement (synthetic input + real pfSense) |
| จำนวน scenario | 4 (A1–A4) |
| จำนวน trial ต่อ scenario | 30 |
| จำนวน trace ทั้งหมด | 120 |
| เกณฑ์ correlation | `min_events = 5`, `window_max = 10.0 s` |
| pfSense | 192.168.227.150, table `ITIS_BLOCK_TEST` |
| กลไก enforcement | SSH → `pfctl -t ITIS_BLOCK_TEST -T add <ip>` + read-back verify |
| SSH timeout | 10 s |
| retry ต่อ trial | สูงสุด 2 ครั้ง (เฉพาะ `EnforcementError`) หน่วง 2 s |
| block duration | 10 s (พารามิเตอร์ของการทดลองเท่านั้น ไม่มีผลต่อ T0–T5) |
| source IP ที่ใช้ทดสอบ | 198.51.100.77 (TEST-NET-2), allowlisted: 203.0.113.9 |
| ทุก record ติดป้าย | `input_mode = "synthetic"` |

### นิยาม scenario

| Scenario | เงื่อนไขนำเข้า | ผลที่คาดหวัง | กฎที่ทำงาน |
|---|---|---|---|
| A1 | 4 events (ต่ำกว่า `min_events`) | ไม่เกิด decision | correlation ไม่ match |
| A2 | severity 3 กระจาย 5 ปลายทาง (MEDIUM) | `ALERT` | RULE-002 |
| A3 | severity 1 เป้าหมายเดียว 5 ครั้ง (CRITICAL) | `BLOCK` | RULE-001 |
| A4 | source อยู่ใน allowlist + severity 1 | `NO_AUTO_BLOCK` | RULE-003 (มาก่อน RULE-001) |

การทดลองนี้ไม่มี scenario ที่ให้ผลลัพธ์ `MONITOR` โดยเจตนา เนื่องจากเมื่อ correlation
match ที่ `min_events = 5` ค่า frequency factor จะถูก clamp ขึ้นสูงจนคะแนนความเสี่ยง
แทบไม่มีทางตกลงไปถึงระดับ LOW ซึ่งเป็นเงื่อนไขเดียวที่จะ fall through ไปเป็น `MONITOR`
ได้ — เป็นคุณสมบัติของ risk model เอง `MONITOR` จึงถูกทดสอบในระดับ unit test ของ
RuleEngine แทน

### นิยาม latency แต่ละช่วง

| Metric | ช่วงเวลาที่วัด | ครอบคลุม |
|---|---|---|
| Detection | t0 (รับ event) → t1 (correlation match) | การ normalize และ correlate เหตุการณ์ |
| Decision | t1 → t3 (ได้ decision) | risk scoring + rule evaluation |
| Enforcement | t4 (ส่งคำสั่ง) → t5 (ยืนยันสำเร็จ) | SSH + `pfctl` + read-back verification |
| End-to-End | t0 → t5 | รวมทุกช่วงข้างต้น |

เวลาทั้งหมดวัดด้วย monotonic clock ภายใน trace เดียวกัน จึงใช้เปรียบเทียบข้าม process ไม่ได้
แต่ใช้เป็นส่วนต่างภายใน trace ได้อย่างถูกต้อง

## 4.2 ผลด้านความถูกต้องเชิงหน้าที่ (Functional Results)

| Scenario | decision ที่ได้ | ตรงกับที่คาดหวัง | จำนวน trial |
|---|---|---|---|
| A1 | ไม่มี decision | ✓ | 30/30 |
| A2 | `ALERT` | ✓ | 30/30 |
| A3 | `BLOCK` | ✓ | 30/30 |
| A4 | `NO_AUTO_BLOCK` | ✓ | 30/30 |
| **รวม** | | **120/120** | **120** |

ตัวชี้วัดความสมบูรณ์ของชุดข้อมูล:

| รายการ | ค่า |
|---|---|
| decisions ตรงตามที่คาดหวัง | 120 / 120 |
| infrastructure failure | 0 |
| trial ที่ต้อง retry | 0 |
| duplicate trial | 0 |
| JSON parse error | 0 |
| trace ที่มี `trial_status = SUCCESS` | 120 / 120 |
| trace ที่มี `enforcement_ok = true` | 120 / 120 |

ใน A3 ทั้ง 30 trial การเพิ่ม IP เข้า table ของ pfSense สำเร็จและผ่านการ read-back
verification ทุกครั้ง โดยไม่เกิด SSH timeout เลย และหลังจบการทดลองได้ตรวจสอบว่า
table `ITIS_BLOCK_TEST` ว่างเปล่า ยืนยันว่ากระบวนการ cleanup ของทุก trial ทำงานครบถ้วน
ไม่มี block ตกค้างบนอุปกรณ์

## 4.3 ผลด้านเวลาตอบสนอง (Latency Results)

การวิเคราะห์ latency ใช้เฉพาะ trace ที่ผ่านเกณฑ์ valid คือเป็น `BLOCK` มีค่า latency
ครบทุกช่วงและไม่ติดลบ ได้จำนวน **n = 30** ซึ่งเป็น A3 ครบทั้ง 30 trial โดยไม่มี trial ใด
ถูกคัดออกจากเกณฑ์ latency ส่วนอีก 90 record ถูกคัดออกเพราะไม่ใช่ `BLOCK` จึงไม่มี
enforcement latency ให้วัดตามนิยาม — **ไม่ใช่ trial ที่ล้มเหลว**

### ตารางที่ 4.1 สถิติ latency ของ engine (n = 30, หน่วย µs)

| Metric | Median | Q1 | Q3 | IQR | Min | Max | P95 |
|---|---|---|---|---|---|---|---|
| Detection | 5.80 | 5.60 | 6.07 | 0.47 | 5.00 | 7.40 | 6.94 |
| Decision | 36.00 | 34.95 | 36.92 | 1.97 | 21.10 | 40.20 | 39.16 |

### ตารางที่ 4.2 สถิติ latency ของ enforcement (n = 30, หน่วย ms)

| Metric | Median | Q1 | Q3 | IQR | Min | Max | P95 |
|---|---|---|---|---|---|---|---|
| Enforcement | 537.23 | 524.00 | 579.17 | 55.17 | 482.22 | 981.76 | 626.14 |
| End-to-End | 537.27 | 524.04 | 579.21 | 55.17 | 482.27 | 981.80 | 626.18 |

**รูปที่ 4.1** `latency_boxplot_engine.png` — การกระจายของ Detection และ Decision (µs)
**รูปที่ 4.2** `latency_boxplot_enforcement.png` — การกระจายของ Enforcement และ End-to-End (ms)

กราฟถูกแยกเป็นสองรูปเนื่องจากสเกลของทั้งสองกลุ่มต่างกันประมาณ 10⁵ เท่า
หากแสดงในรูปเดียวกัน Detection และ Decision จะแบนราบติดแกนจนอ่านค่าไม่ได้

## 4.4 การตีความผล (Interpretation)

**เวลาส่วนใหญ่เกิดขึ้นที่ enforcement path** Detection และ Decision รวมกันมีค่า median
41.80 µs ขณะที่ End-to-End มีค่า median 537.27 ms สะท้อนว่าในสภาพแวดล้อมการทดลองนี้
latency ส่วนใหญ่เกิดใน enforcement path จากค่า median พบว่า enforcement latency
คิดเป็นประมาณ 99.993% ของ end-to-end latency ในการทดลองชุดนี้ (ค่าดังกล่าวคำนวณจาก
ค่าที่ปัดเศษในตารางที่ 4.2 จึงเป็นค่าโดยประมาณ)

เพื่อประกอบการพิจารณา ขั้นตอนที่แต่ละช่วงต้องทำมีลักษณะต่างกันดังนี้ Detection และ
Decision เป็นการคำนวณในหน่วยความจำภายใน process เดียว ส่วน enforcement path
ประกอบด้วยการเปิด SSH session ไปยัง pfSense เรียก `pfctl -T add` แล้วอ่าน table
กลับมายืนยันด้วย `pfctl -T show` ซึ่งเป็นการสื่อสารข้ามเครื่องหลายรอบ

**การกระจายของ enforcement ค่อนข้างแคบแต่มี outlier** ค่า IQR เท่ากับ 55.17 ms
(Q1 = 524.00, Q3 = 579.17) แสดงว่า trial ส่วนใหญ่ใช้เวลาใกล้เคียงกัน แต่มี trial หนึ่ง
ที่ใช้เวลา 981.76 ms สูงกว่า median เกือบเท่าตัว ค่า P95 ที่ 626.14 ms สะท้อนว่า
ความแปรปรวนนี้กระทบเพียงส่วนน้อยของการทดลอง trial ดังกล่าวยังคงมีสถานะ `SUCCESS`
และ `enforcement_ok = true` โดยไม่เกิด retry จึงไม่ใช่ความล้มเหลว แต่แสดงถึงความแปรปรวน
ของ enforcement path ภายใต้สภาพแวดล้อมการทดลอง ทั้งนี้ชุดข้อมูลไม่ได้แยกวัดเวลาย่อย
ภายใน enforcement path จึงไม่สามารถระบุสาเหตุของค่าดังกล่าวได้ สาเหตุที่เป็นไปได้
อาจเกี่ยวข้องกับความแปรปรวนของ SSH หรือ network path แต่ไม่มีหลักฐานในชุดข้อมูลนี้
ที่ยืนยันได้

**ข้อจำกัดของการอ้างผล** ค่าเหล่านี้เป็นค่าที่สังเกตได้ในสภาพแวดล้อมห้องปฏิบัติการเฉพาะนี้
ไม่ใช่ข้อสรุปเชิงสมรรถนะที่ใช้ได้ทั่วไป การเปลี่ยนอุปกรณ์ ความเร็วเครือข่าย หรือภาระงาน
ของ hypervisor อาจทำให้ค่า enforcement latency เปลี่ยนไปอย่างมีนัยสำคัญ

## 4.5 ข้อจำกัดของการทดลอง (Limitations)

1. **ไม่ได้วัด detection latency ของ Suricata จริง** เหตุการณ์นำเข้าเป็น synthetic EVE
   ที่ป้อนเข้า pipeline โดยตรง ค่า Detection ในตารางที่ 4.1 จึงหมายถึงเวลาที่ engine ใช้
   ในการ correlate เหตุการณ์ที่ได้รับแล้วเท่านั้น ไม่รวมเวลาที่ Suricata ใช้ตรวจจับ
   และเขียน event ออกมา การวัด Suricata-to-pfSense แบบ end-to-end จริงต้องใช้
   Mode C ซึ่งอยู่นอกขอบเขตของชุดข้อมูลนี้

2. **ไม่ได้ประเมินความแม่นยำในการตรวจจับ** การทดลองนี้ไม่มี labeled attack dataset
   จึงไม่สามารถสรุปค่า detection accuracy, false positive rate หรือ false negative rate ได้
   สิ่งที่การทดลองพิสูจน์คือ pipeline ตัดสินใจ**ตรงตามกฎที่กำหนดไว้**เมื่อได้รับ input
   ที่ควบคุมได้ ไม่ใช่ว่าระบบตรวจจับการโจมตีจริงได้แม่นยำเพียงใด

3. **จำนวน trial เหมาะกับการ characterize ไม่ใช่ statistical inference** 30 trial ต่อ
   scenario เพียงพอสำหรับอธิบายลักษณะการกระจายของ latency แต่ไม่ได้ออกแบบมาเพื่อ
   ทดสอบสมมติฐานทางสถิติ หรือสร้าง confidence interval ที่มีนัยสำคัญ

4. **ผลผูกกับสภาพแวดล้อมเฉพาะ** ค่า enforcement latency ขึ้นกับ SSH implementation
   เวอร์ชันของ pfSense ทรัพยากรของ VM และสภาพเครือข่ายใน GNS3 การทำซ้ำบนสภาพแวดล้อมอื่น
   ควรคาดหวังค่าที่ต่างออกไป

5. **scenario ครอบคลุมเฉพาะเส้นทางหลัก 4 เส้น** ไม่ได้ทดสอบกรณีที่เหตุการณ์มาพร้อมกัน
   จากหลาย source, กรณี pfSense ปฏิเสธคำสั่ง หรือกรณี table เต็ม ซึ่งเป็นสถานการณ์ที่
   ระบบจริงอาจพบได้
