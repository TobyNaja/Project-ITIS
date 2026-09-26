# บทที่ 7 สรุปผลและข้อเสนอแนะ

## 7.1 สรุปการดำเนินงาน

โครงงานนี้พัฒนาต้นแบบระบบที่เชื่อม IDS กับ firewall ให้ตอบสนองต่อรูปแบบเหตุการณ์ที่กำหนดไว้ล่วงหน้าได้โดยอัตโนมัติ ระบบประกอบด้วย Suricata ที่ตรวจจับและ
ส่งออกเหตุการณ์เป็น EVE JSON, security engine ที่เขียนด้วย Python และ pfSense ที่บังคับใช้การปิดกั้นผ่าน pf table โดยใช้ SQLite เก็บ audit trail
engine ทำงานตามลำดับ ingestion → correlation → risk assessment → rule engine → enforcement → verification → audit และมี lifecycle
ที่ยกเลิกการปิดกั้นเมื่อครบ 300 s นอกจากนี้มีเส้นทางคู่ขนานที่ตรวจสุขภาพเชิงฟังก์ชันของ Suricata และกู้คืนได้ไม่เกิน 3 ครั้ง

ระบบถูกทดลองในห้องปฏิบัติการเสมือน (pfSense CE 2.7.2 และ Suricata 7.0.8 บน GNS3/VMware) ตามสถานการณ์ T1–T11 ของ Blueprint รวม
58 runs ชุดข้อมูลหลักใช้ controlled EVE injection ส่วน T8 และ T9 ใช้ fault injection ชุดข้อมูลผ่าน validation และถูก freeze ก่อนวิเคราะห์ ส่วนประกอบที่อยู่ใน
การออกแบบแต่ไม่ได้ติดตั้งคือ Prometheus และ Grafana

## 7.2 คำตอบของคำถามวิจัย

> *Can rule-based correlation of IDS events reduce the time required to enforce a predefined firewall response in a controlled
> network environment?*

**สิ่งที่ผลการทดลองแสดง** — ภายใต้เงื่อนไขการทดลองที่กำหนด ได้แก่ ห้องปฏิบัติการที่ควบคุมได้, controlled EVE injection, กฎที่กำหนดไว้ล่วงหน้า และ
Weight Set A การ correlate IDS events ด้วยกฎทำให้ firewall response ที่กำหนดไว้ถูกบังคับใช้และยืนยันผลบน pfSense ได้โดยอัตโนมัติ
ไม่มีขั้นตอนใดที่ต้องให้ผู้ดูแลลงมือ

- ใน T4 ทุก run ผ่านเส้นทาง correlation → decision (RULE-001) → pf table add → read-back verification ครบ (5/5) และใน T7 ผลการอ่านกลับของ engine
  ตรงกับการอ่าน `pfctl` ที่ทำแยก (5/5)
- end-to-end response time (M4) ของ T4 มีค่าเฉลี่ย **1,593.4 ms** (n = 5, ช่วง 1,513.4–1,695.5 ms) นับจาก timestamp ของ event ถึงเวลาที่ยืนยันว่า block
  มีผลใน pf table
- เวลาส่วนใหญ่อยู่ที่การส่ง event เข้า engine (M1 ประมาณ 58% ของ M4) และขั้น enforcement + verification (M3 ประมาณ 37%) ส่วน correlation และการตัดสินใจ
  ใช้ประมาณ 4% (M2 mean 69.2 ms ในกลุ่ม T3 + T4)

**สิ่งที่ผลการทดลองไม่ได้แสดง** — การทดลองไม่ได้วัดเวลาที่ผู้ดูแลใช้ตอบสนองด้วยมือ ขอบเขตของโครงงาน (หัวข้อ 1.5) กำหนดให้ใช้ end-to-end latency ของเส้นทาง
อัตโนมัติแทนการเปรียบเทียบนี้ จึง**ไม่มีหลักฐานเชิงเปรียบเทียบว่าเวลาลดลงเท่าใด** รายงานนี้ไม่อ้างเปอร์เซ็นต์ของเวลาที่ลดลง และไม่นำค่าที่วัดได้ไปอนุมานเป็นประสิทธิภาพ
ในระบบใช้งานจริง

**คำตอบ** — ภายในขอบเขตข้างต้น คำตอบคือ rule-based correlation ทำให้การบังคับใช้ firewall response ที่กำหนดไว้เกิดขึ้นและยืนยันผลได้โดยอัตโนมัติ ด้วย
end-to-end response time ที่วัดได้ในระดับประมาณ 1.6 s ใน T4 โดยไม่ต้องรอการตัดสินใจของมนุษย์ ส่วนคำถามว่าเวลานี้ "ลดลง" เท่าใดเมื่อเทียบกับการตอบสนองด้วยมือ
การทดลองนี้ตอบเชิงปริมาณไม่ได้

**บทบาทของ risk assessment** — T11 แสดงว่า เมื่อใช้ input pattern เดิม การเปลี่ยน weight set เปลี่ยนคะแนนและระดับความเสี่ยง (A 79.5 HIGH · B 80.5
CRITICAL · C 78.5 HIGH) แต่ไม่เปลี่ยน action ทั้งสามชุดได้ RULE-001 BLOCK ที่ verify สำเร็จ เหตุผลเป็นเชิงโครงสร้าง เพราะเงื่อนไขของ rule ใช้ severity,
จำนวน event, time window และ allowlist ไม่ใช้ risk score หรือ risk level ในระบบนี้ เวลาที่ใช้บังคับใช้การตอบสนองจึงถูกกำหนดโดย correlation และกฎ ส่วน risk
assessment ทำหน้าที่ให้การประเมินแบบถ่วงน้ำหนักที่บันทึกไว้เพื่ออธิบายการตัดสินใจ

Risk assessment provides a weighted assessment of the correlated pattern, while the Rule Engine determines the response action
according to predefined conditions.

## 7.3 สรุปผลตามวัตถุประสงค์

**ตาราง 7.1** สรุปผลตามวัตถุประสงค์ (รายละเอียดในตาราง 6.8)

| Objective | สถานะ | สรุป |
|---|---|---|
| O1 รับ security event จาก Suricata | บรรลุ | alert ที่ inject ถูกบันทึกครบ 170/170 |
| O2 Event correlation | บรรลุ | pattern ที่ถึงเกณฑ์ถูก correlate ส่วน pattern ที่ต่ำกว่าเกณฑ์ (T2, T10) ไม่ถูก correlate |
| O3 แบบจำลองความเสี่ยงแบบถ่วงน้ำหนัก | บรรลุ | คะแนนตรงกับ model ทุก run และ weight set A/B/C ให้ค่าตามน้ำหนัก |
| O4 Rule-based automated response | บรรลุ | RULE-001/002/003 ให้ action ตามที่กำหนดทุก run |
| O5 Temporary block บน pfSense | บรรลุ | BLOCK SUCCESS + VERIFIED 18/18 |
| O6 Auto-unblock | บรรลุ | ทุก block ถูกปลดและ verify สำเร็จ 18/18 · T6 5/5 |
| O7 ตรวจว่า firewall บังคับใช้จริง | บรรลุบางส่วน | ยืนยันในระดับสถานะของ firewall (read-back) · ไม่ได้ทดสอบเส้นทางของทราฟฟิกโดยตรง |
| O8 Allowlist safety | บรรลุ | source ใน allowlist ไม่ถูก block 5/5 |
| O9 Audit trail ที่อธิบายได้ | บรรลุ | สายย้อนกลับ event → pattern → risk → decision → action ครบ พร้อมเหตุผลของ rule |
| O10 Functional recovery (retry ≤ 3) | บรรลุ | กู้คืนได้ 5/5 (T8) · หยุดที่ 3 attempts และเข้า CRITICAL 5/5 (T9) |
| O11 วัดประสิทธิภาพ | บรรลุบางส่วน | วัด latency, scenario-defined unnecessary block (M7 0/25) และ sensitivity ได้ · overhead ไม่ได้วัด |

บรรลุ 9 จาก 11 วัตถุประสงค์ และบรรลุบางส่วน 2 ข้อ (O7, O11) ทั้งสองข้อมาจากข้อจำกัดของสภาพแวดล้อมการทดลอง ไม่ใช่จากการทำงานที่ผิดพลาดของระบบ

## 7.4 ข้อจำกัดของโครงงาน

ข้อจำกัดทั้งหมดอยู่ในหัวข้อ 6.8 ข้อที่มีผลต่อการนำข้อสรุปไปใช้มากที่สุดได้แก่

1. **สภาพแวดล้อม** — ทดลองในห้องปฏิบัติการเสมือนที่มีทราฟฟิกน้อย ใช้ input แบบ controlled EVE injection จาก source เดียว และมี 5 runs ต่อ test
   ผลจึงไม่ใช่ประสิทธิภาพระดับ production
2. **ความหมายของ latency** — M1 เป็น EVE ingestion latency ไม่ใช่เวลาตรวจจับ packet ของ Suricata และ M3 แยกเวลาคำสั่งกับเวลา verification ไม่ได้
3. **ไม่มี manual baseline** — ไม่สามารถระบุว่าเวลาลดลงเท่าใดเมื่อเทียบกับการตอบสนองด้วยมือ
4. **การยืนยันการบังคับใช้** — ยืนยันได้ในระดับ pf table read-back เท่านั้น
5. **แบบจำลองความเสี่ยง** — เป็นแบบจำลองถ่วงน้ำหนักที่ใช้กฎสำหรับการทดลองนี้ ไม่ใช่มาตรฐานสากล และไม่ได้ทดสอบกรณี known lab asset (C = 30)
6. **การกู้คืน** — ไม่มีช่วงรอระหว่าง attempt และไม่ได้ยืนยันว่า engine ยังประมวลผล event ในช่วง CRITICAL เวลากู้คืนที่วัดได้ไม่ตรงนิยาม M11
7. **Monitoring** — ไม่ได้ติดตั้ง Prometheus/Grafana จึงไม่มีข้อมูล overhead
8. **นาฬิกาและ revision** — ลด clock offset ระหว่าง SEC01 กับ pfSense ให้ใกล้ศูนย์ไม่ได้ (ไม่กระทบ M1–M4 ในชุดข้อมูลหลัก) และ T11 รันบน revision ต่างจาก T1–T10
9. **เวอร์ชันของ Python** — engine ทดสอบบน Python 3.14.5 เท่านั้น ยังไม่ได้ทดสอบบน Python 3.10 ตามที่ Blueprint ระบุไว้เป็น requirement

## 7.5 แนวทางการพัฒนาต่อ

**ปรับปรุงการวัดและการทดลอง**

- เพิ่มจุดเวลาระหว่างการส่งคำสั่งกับการอ่านกลับใน enforcement path เพื่อรายงาน command round-trip และ verification time แยกกันตามที่ Blueprint กำหนด
- บันทึกเวลาที่ health check ตรวจพบ failure เพื่อวัด M11 ตามนิยาม (`T_service_healthy − T_failure_detected`)
- ติดตั้ง Prometheus/Grafana หรือเครื่องมือเก็บข้อมูลทรัพยากรอื่น เพื่อวัด overhead (CPU/RAM/PPS) ของ engine (M13)
- ทดสอบ traffic-path verification ด้วย host จริงที่ถูก block และทดสอบกรณี known lab asset เมื่อมี asset ที่ยืนยันบทบาทได้
- ทดลองด้วยทราฟฟิกจริงผ่าน Suricata, event ที่กระจายตลอด window, หลาย source พร้อมกัน และเพิ่มจำนวนรอบ
- ออกแบบการเปรียบเทียบกับการตอบสนองด้วยมือที่วัดได้อย่างเที่ยงตรง หากต้องการตอบคำถามเรื่อง "ลดเวลา" เชิงปริมาณ
- ทดสอบ engine บน Python 3.10 เพื่อยืนยันความเข้ากันได้ตาม requirement

**ปรับปรุงระบบ**

- เพิ่มช่วงรอหรือ backoff ระหว่าง recovery attempt และทดสอบการประมวลผล event ระหว่างสถานะ CRITICAL
- แยก stderr ของ SSH client ออกจากข้อความ error ของ `recovery_events` ให้ข้อความระบุสาเหตุของ failure ได้ตรง
- ถ้าต้องการให้ risk assessment มีผลต่อการตัดสินใจ ต้องออกแบบเงื่อนไขของ rule ที่ใช้ risk level อย่างชัดเจน และทดสอบ sensitivity ใหม่ เพราะใน implementation
  ปัจจุบันไม่มีเส้นทางดังกล่าว
- การปิดกั้นแบบปรับระยะเวลาเพิ่มขึ้น (adaptive/escalating blocking) ซึ่งอยู่นอกขอบเขตของโครงงานนี้
