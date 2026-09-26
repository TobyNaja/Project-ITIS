# บทที่ 2 ทฤษฎีและงานที่เกี่ยวข้อง

บทนี้อธิบายแนวคิดและเทคโนโลยีที่จำเป็นต่อการเข้าใจระบบที่พัฒนา ได้แก่ firewall และ pfSense, ระบบตรวจจับการบุกรุกและ
Suricata, รูปแบบข้อมูล EVE JSON, การเชื่อมโยงเหตุการณ์, การประเมินความเสี่ยง, การตอบสนองอัตโนมัติ และการกู้คืนบริการ
รวมถึงงานวิจัยที่เกี่ยวข้อง เพื่อวางตำแหน่งของโครงงานนี้เทียบกับแนวคิดที่มีอยู่

## 2.1 ระบบรักษาความปลอดภัยเครือข่าย

การรักษาความปลอดภัยของเครือข่ายประกอบด้วยหลายหน้าที่ที่ทำงานร่วมกัน ได้แก่ การป้องกัน (เช่น firewall ที่กำหนดว่าทราฟฟิกใด
ผ่านได้), การตรวจจับ (เช่น IDS ที่วิเคราะห์ทราฟฟิกเพื่อหาพฤติกรรมที่น่าสงสัย) และการตอบสนองต่อเหตุการณ์ที่ตรวจพบ
แนวทางของ NIST SP 800-61 Revision 3 จัดกิจกรรมเหล่านี้ตามหน้าที่ (Functions) ของ Cybersecurity Framework (CSF) 2.0
โดยระบุว่า Govern, Identify และ Protect ช่วยป้องกันและเตรียมความพร้อม ส่วน Detect, Respond และ Recover ช่วยให้องค์กร
"discover, manage, prioritize, contain, eradicate, and recover from cybersecurity incidents" [9] โครงงานนี้อยู่ในส่วนของ
Detect, Respond และ Recover คือรับผลการตรวจจับจาก IDS ตอบสนองด้วย firewall และกู้คืน IDS เมื่อทำงานผิดปกติ

## 2.2 Firewall และ pfSense

Firewall ทำหน้าที่ควบคุมทราฟฟิกระหว่างเครือข่ายตามกฎที่กำหนด pfSense เป็น "a free open source customized distribution
of FreeBSD tailored for use as a firewall and router entirely managed by an easy-to-use web interface" [1] โดยใช้ pf
(packet filter) ของ FreeBSD เป็นกลไกกรองแพ็กเก็ต (pfSense CE 2.7.2 ที่ใช้ในห้องปฏิบัติการสร้างบน FreeBSD 14.0-CURRENT
รายงานนี้จึงอ้างคู่มือ pf ของ FreeBSD 14.0 [3])

กลไกที่เกี่ยวข้องโดยตรงกับโครงงานคือ **table** ของ pf ซึ่งเป็น "named structures which can hold a collection of addresses and
networks" และการค้นหาใน table "are relatively fast, making a single rule with tables much more efficient ... than a large number
of rules which differ only in IP address" [3] เนื้อหาของ table แก้ไขได้ขณะระบบทำงานด้วยคำสั่ง `pfctl` โดยไม่ต้องโหลด
ชุดกฎใหม่ [3] ใน pfSense นั้น alias จะถูกคัดลอกเข้าเป็น table ภายในเมื่อ firewall โหลดชุดกฎ "which it uses to quickly perform
address matches" [2] คุณสมบัตินี้ทำให้การปิดกั้นแบบชั่วคราวทำได้ด้วยการเพิ่มและลบ IP address ใน table ที่มีกฎปิดกั้นอ้างถึงอยู่แล้ว
แทนการสร้างหรือแก้กฎทีละรายการ และสามารถอ่านเนื้อหาของ table กลับมาเพื่อตรวจสอบสถานะได้

## 2.3 Intrusion Detection System และ Suricata

ระบบตรวจจับการบุกรุก (IDS) วิเคราะห์ทราฟฟิกเครือข่ายเพื่อหาเหตุการณ์ที่ตรงกับรูปแบบของการโจมตีหรือพฤติกรรมที่น่าสงสัย แล้วสร้าง
การแจ้งเตือน (alert) IDS แบบ signature-based ตัดสินจากกฎ (rule/signature) ที่กำหนดไว้ล่วงหน้า ความสามารถในการตรวจจับจึงขึ้นกับ
ชุดกฎที่ใช้

Suricata คือ "a high performance Network IDS, IPS and Network Security Monitoring engine" เป็นซอฟต์แวร์ open source ที่ดูแลโดย
Open Information Security Foundation (OISF) [4] แต่ละ signature ของ Suricata มีระดับความสำคัญ (priority) ที่มาจาก classtype
หรือกำหนดด้วย keyword `priority` ซึ่งมีค่า 1–255 "The highest priority is 1" และค่าที่ใช้ทั่วไปคือ 1 ถึง 4 [7] ดังนั้นค่าตัวเลข
ที่น้อยกว่าหมายถึงเหตุการณ์ที่สำคัญกว่า

## 2.4 Suricata EVE JSON

EVE คือช่องทางส่งออกข้อมูลของ Suricata ที่ "outputs alerts, anomalies, metadata, file info and protocol specific records through
JSON" [5] ทุก record ของ EVE มีฟิลด์ร่วม เช่น `timestamp`, `event_type` และ network tuple (`src_ip`, `src_port`, `dest_ip`,
`dest_port`, `proto`) [6] record ประเภท `alert` มี object `alert` ที่ประกอบด้วย `signature_id`, `signature`, `severity` และ
`category` [6]

นอกจาก alert แล้ว EVE ยังส่งออก record ประเภท `stats` ซึ่งเป็นตัวนับสถิติการทำงานของ Suricata ตามช่วงเวลาที่ตั้งค่า
(กำหนดได้ว่าจะรวมทุก thread, แยก thread หรือรวมค่าส่วนต่าง) [5] record ประเภทนี้ถูกเขียนออกมาเป็นระยะไม่ว่ามีทราฟฟิกหรือไม่
จึงใช้เป็นสัญญาณว่า Suricata ยังทำงานและยังเขียนผลลัพธ์ออกมาได้ ซึ่งเป็นพื้นฐานของการตรวจสุขภาพเชิงฟังก์ชันในหัวข้อ 2.9

การที่ EVE เป็น JSON หนึ่ง record ต่อบรรทัดทำให้โปรแกรมภายนอกอ่านต่อท้ายไฟล์ (tail) และแปลงข้อมูลได้โดยตรง
โดยไม่ต้องแก้ไข Suricata

## 2.5 Event Correlation

IDS อาจสร้าง alert จำนวนมาก และ alert เดี่ยวหลายรายการอาจเป็นผลบวกลวงหรือเป็นส่วนหนึ่งของเหตุการณ์เดียวกัน การเชื่อมโยงเหตุการณ์
(alert correlation) คือการรวมหรือเชื่อมความสัมพันธ์ของ alert หลายรายการเพื่อให้ได้ภาพที่มีความหมายมากขึ้น Debar และ Wespi [12]
เสนอการรวม (aggregation) และเชื่อมโยง alert จาก IDS เพื่อลดจำนวน alert ที่ผู้ดูแลต้องพิจารณา Valeur และคณะ [13] เสนอแบบจำลอง
การเชื่อมโยง alert ที่ประกอบด้วยหลายขั้นตอน เช่น การปรับรูปแบบข้อมูล (normalization) การรวม alert ที่เกี่ยวข้อง และการประเมินผลกระทบ
ในรูปแบบ framework

รูปแบบการเชื่อมโยงที่ง่ายที่สุดคือการรวม alert ตามคุณลักษณะร่วม เช่น แหล่งที่มา (source IP) ภายในช่วงเวลาที่กำหนด (time window)
แล้วพิจารณาจำนวนและความรุนแรงของ alert ในกลุ่มนั้น โครงงานนี้ใช้รูปแบบดังกล่าว คือรวม alert จาก source IP เดียวกันภายในช่วงเวลา
และตัดสินจากความถี่และความรุนแรง ไม่ได้ใช้การเชื่อมโยงแบบหลายขั้นตอน (multi-step attack correlation) ตามแนวของ [13]

## 2.6 Risk Assessment

### 2.6.1 CVSS v4.0

Common Vulnerability Scoring System (CVSS) v4.0 ของ FIRST เป็นมาตรฐานสำหรับให้คะแนนความรุนแรงของช่องโหว่ ประกอบด้วยกลุ่ม metric
สี่กลุ่ม ได้แก่ Base, Threat, Environmental และ Supplemental และกำหนดมาตราส่วนเชิงคุณภาพ None (0.0), Low (0.1–3.9),
Medium (4.0–6.9), High (7.0–8.9) และ Critical (9.0–10.0) [8] CVSS แยกความรุนแรงออกจากความเสี่ยงอย่างชัดเจน โดยแนะนำให้ผู้ใช้
เสริม Base metrics ด้วย Threat และ Environmental metrics เพื่อให้ได้ "a more comprehensive input to risk assessment specific to
their organization" [8]

CVSS ออกแบบมาเพื่อให้คะแนน**ช่องโหว่** ไม่ใช่เพื่อให้คะแนนรูปแบบของ alert จาก IDS แนวคิดที่โครงงานนำมาใช้จาก CVSS จึงมีเพียง
การแยกระดับความรุนแรงเป็นช่วงเชิงคุณภาพ และแนวคิดว่าคะแนนความรุนแรงควรถูกปรับด้วยบริบทของสภาพแวดล้อม

### 2.6.2 NIST Incident Handling

NIST SP 800-61 Revision 2 (2012) อธิบายวงจรการรับมือเหตุการณ์เป็นระยะต่อเนื่อง ได้แก่ Preparation; Detection and Analysis;
Containment, Eradication and Recovery; และ Post-Incident Activity [10] Revision 3 (เมษายน 2025) แทนที่ Revision 2 และเปลี่ยนมาใช้
แบบจำลองตามหน้าที่ของ CSF 2.0 โดยให้เหตุผลว่าเหตุการณ์ในปัจจุบันเกิดบ่อยและกินเวลานานกว่าเดิม การรับมือเหตุการณ์จึงควรเป็นส่วนหนึ่ง
ของการบริหารความเสี่ยงด้านไซเบอร์ที่ทำอย่างต่อเนื่อง [9] แนวคิดที่โครงงานนำมาใช้คือลำดับ ตรวจพบ → วิเคราะห์และจัดลำดับความสำคัญ →
ควบคุม (contain) → กู้คืน และหลักว่าการตอบสนองต้องมีบันทึกเพื่อการสื่อสารและการเรียนรู้ภายหลัง

### 2.6.3 Risk Model ที่ใช้ในโครงงาน

CVSS และ NIST SP 800-61 เป็น**พื้นฐานเชิงแนวคิดและแหล่งอ้างอิง**ของการออกแบบเท่านั้น แบบจำลองความเสี่ยงของโครงงานเป็นแบบจำลองที่
ผู้พัฒนาออกแบบขึ้นสำหรับสภาพแวดล้อมการทดลองที่ควบคุมได้ **ไม่ได้นำสูตรของ CVSS มาใช้โดยตรง** และไม่ได้ให้คะแนนช่องโหว่

> The proposed risk scoring model is a rule-based weighted model developed for the controlled experimental environment,
> informed by established cybersecurity severity and incident assessment concepts (CVSS v4.0, NIST Incident Handling).
> The weights and normalization mappings are experimental design parameters and are not claimed to represent a universal
> industry standard.

แบบจำลองนี้รวมปัจจัยสี่ด้านของรูปแบบเหตุการณ์ที่เชื่อมโยงแล้ว ได้แก่ ความรุนแรง (severity), ความถี่ (frequency), ความกระชับของเวลา
(temporal) และบริบทของแหล่งที่มา (source context) เป็นคะแนนถ่วงน้ำหนัก และแบ่งระดับเป็น LOW, MEDIUM, HIGH และ CRITICAL
โดยใช้แนวคิดการแบ่งช่วงเชิงคุณภาพแบบเดียวกับ [8] แต่ใช้ช่วงคะแนนของตนเอง ค่าน้ำหนักมีสามชุด (Weight Set A, B, C) เพื่อใช้
วิเคราะห์ความไวของแบบจำลอง รายละเอียดของสูตร ตารางการแปลงค่า และเกณฑ์ระดับอยู่ในบทที่ 3

สิ่งสำคัญในการออกแบบคือ คะแนนความเสี่ยงทำหน้าที่**ประเมินและอธิบาย**รูปแบบเหตุการณ์ ส่วนการตัดสินใจตอบสนองเป็นหน้าที่ของกฎ
(หัวข้อ 2.7) ซึ่งทำให้ระบบอธิบายได้ว่าการตอบสนองแต่ละครั้งเกิดจากเงื่อนไขใด

## 2.7 Rule-Based Automated Response

ระบบตอบสนองต่อการบุกรุก (Intrusion Response System: IRS) คือระบบที่ดำเนินการตอบโต้เมื่อตรวจพบการบุกรุก Stakhanova และคณะ [14]
จำแนก IRS ตามคุณลักษณะ เช่น ระดับความเป็นอัตโนมัติ (notification, manual, automatic) และวิธีเลือกการตอบสนอง ซึ่งรวมถึงการเลือกแบบ
คงที่ (static mapping) ที่จับคู่เหตุการณ์กับการตอบสนองที่กำหนดไว้ล่วงหน้า Shameli-Sendi และคณะ [15] นำเสนออนุกรมวิธานของ IRS
ร่วมกับการประเมินความเสี่ยงของการบุกรุก และชี้ว่าการตอบสนองควรพิจารณาทั้งความเสี่ยงของการโจมตีและผลกระทบของการตอบสนองเอง
Inayat และคณะ [16] ทบทวนพารามิเตอร์การออกแบบ IRS และความท้าทาย เช่น ความถูกต้องของการตอบสนอง และผลกระทบต่อการให้บริการเมื่อตอบสนองผิด

ระบบในโครงงานนี้จัดเป็น IRS แบบอัตโนมัติที่ใช้การจับคู่แบบคงที่ด้วยกฎ (rule-based) กฎแต่ละข้อระบุเงื่อนไขของรูปแบบเหตุการณ์และการตอบสนอง
หนึ่งในสามระดับ ได้แก่ MONITOR, ALERT และ BLOCK ข้อดีคือพฤติกรรมคาดการณ์ได้และตรวจสอบย้อนหลังได้ ข้อจำกัดคือไม่ปรับตัวตามบริบท
ที่ไม่ได้กำหนดไว้ในกฎ

## 2.8 Allowlist และ Fail-Safe Response

การปิดกั้นอัตโนมัติมีความเสี่ยงต่อการให้บริการ เพราะการตอบสนองต่อผลบวกลวงอาจตัดการเชื่อมต่อที่ถูกต้อง [15], [16] กลไกควบคุมที่ใช้ในโครงงาน
ได้แก่

- **Allowlist** — รายการแหล่งที่มาที่เชื่อถือได้ ซึ่งมีผลเหนือการปิดกั้นอัตโนมัติ (enforcement override) เหตุการณ์จากแหล่งเหล่านี้ยังถูกบันทึกและแจ้งเตือน
  แต่ไม่ถูกปิดกั้น
- **Temporary block** — การปิดกั้นมีระยะเวลาจำกัดและยกเลิกเองเมื่อครบเวลา เพื่อให้ผลของการตัดสินใจผิดพลาดย้อนกลับได้
- **Enforcement verification** — การยืนยันว่าคำสั่งมีผลจริงโดยอ่านสถานะของ firewall กลับมา เนื่องจากการที่คำสั่งทำงานสำเร็จไม่ได้รับประกันว่า
  firewall บังคับใช้แล้ว
- **Audit trail** — การบันทึกทุกการตัดสินใจพร้อมเหตุผล เพื่อให้ตรวจสอบย้อนหลังได้ว่าปิดกั้นใคร เมื่อใด ด้วยกฎใด
- **Fail-safe** — เมื่อการตรวจสอบหรือคำสั่งล้มเหลว ระบบต้องบันทึกความล้มเหลวอย่างชัดเจน และไม่รายงานว่าสำเร็จ

## 2.9 Automated Recovery

ระบบตอบสนองอัตโนมัติทำงานได้ก็ต่อเมื่อแหล่งข้อมูลยังทำงานอยู่ การตรวจว่า process ของ IDS ยังอยู่ไม่เพียงพอ เพราะ process อาจอยู่
แต่ไม่ผลิตผลลัพธ์ และการที่ไม่มี alert ก็อาจหมายถึงเครือข่ายเงียบหรือ IDS หยุดทำงานก็ได้ การตรวจสุขภาพเชิงฟังก์ชัน (functional health check)
จึงตรวจจากผลลัพธ์ที่ IDS ต้องผลิตอย่างสม่ำเสมอ ซึ่งในกรณีของ Suricata คือ record `stats` ใน EVE (หัวข้อ 2.4) เมื่อพบว่าผิดปกติ ระบบจะพยายาม
เริ่มบริการใหม่ (restart) และตรวจซ้ำ โดยจำกัดจำนวนครั้ง เพื่อไม่ให้เกิดการลองใหม่ไม่รู้จบ เมื่อครบจำนวนครั้งแล้วยังไม่สำเร็จ ระบบต้องรายงานสถานะ
วิกฤตให้ผู้ดูแลทราบ แนวคิดนี้สอดคล้องกับหน้าที่ Recover ใน [9] แต่มีขอบเขตแคบกว่า คือกู้คืนบริการ IDS เพียงบริการเดียว ไม่ใช่การจัดการบริการ
แบบครบวงจรหรือสถาปัตยกรรม high availability

## 2.10 Security Orchestration / Automated Response

Security Orchestration, Automation and Response (SOAR) คือแนวทางที่เชื่อมเครื่องมือด้านความปลอดภัยหลายชนิดเข้าด้วยกัน และทำให้ขั้นตอนการรับมือ
เหตุการณ์ทำงานอัตโนมัติ Islam และคณะ [11] ทบทวนวรรณกรรมทั้งเชิงวิชาการและเอกสารจากอุตสาหกรรมเกี่ยวกับ security orchestration
โดยนิยามว่า security orchestration คือการบูรณาการเครื่องมือด้านความปลอดภัยจากหลายผู้ผลิตให้ทำงานร่วมกันได้ และจัดหน้าที่หลักเป็นสามกลุ่ม
ได้แก่ unification (รวมเครื่องมือที่หลากหลายเข้าด้วยกัน), orchestration (ประสานการทำงานของเครื่องมือที่รวมแล้ว) และ automation
(ทำให้ขั้นตอนด้านความปลอดภัยทำงานอัตโนมัติ)

โครงงานนี้มีหลักการเดียวกันในขนาดเล็ก คือเชื่อม IDS (Suricata) กับ firewall (pfSense) ผ่านโปรแกรมตัวกลาง แต่ไม่ใช่แพลตฟอร์ม SOAR
เพราะรองรับเพียงเครื่องมือสองชนิดและการตอบสนองที่กำหนดไว้ล่วงหน้า ไม่มี playbook ที่ผู้ใช้กำหนดเอง และไม่มีการประสานกับระบบอื่นขององค์กร

## 2.11 งานวิจัยที่เกี่ยวข้อง

**ตาราง 2.1** งานที่เกี่ยวข้องและความสัมพันธ์กับโครงงาน

| งาน | ประเด็นหลัก | ความสัมพันธ์กับโครงงาน |
|---|---|---|
| Debar และ Wespi (2001) [12] | aggregation และ correlation ของ IDS alert | แนวคิดการรวม alert ก่อนตัดสินใจ |
| Valeur และคณะ (2004) [13] | framework การเชื่อมโยง alert หลายขั้นตอน | โครงงานใช้เฉพาะการเชื่อมโยงตาม source และช่วงเวลา |
| Stakhanova และคณะ (2007) [14] | อนุกรมวิธานของ IRS | จัดโครงงานเป็น IRS อัตโนมัติแบบ static mapping |
| Shameli-Sendi และคณะ (2014) [15] | การประเมินความเสี่ยงร่วมกับการตอบสนองต่อการบุกรุก | แนวคิดประเมินความเสี่ยงก่อนตอบสนอง และผลกระทบของการตอบสนองผิด |
| Inayat และคณะ (2016) [16] | พารามิเตอร์การออกแบบและความท้าทายของ IRS | ความจำเป็นของกลไกควบคุมเมื่อการตอบสนองผิด |
| Islam และคณะ (2019) [11] | ทบทวน security orchestration (SOAR) | วางตำแหน่งโครงงานเป็นการเชื่อมต่อแบบอัตโนมัติขนาดเล็ก |

งานส่วนใหญ่ข้างต้นเป็นกรอบแนวคิดหรืออนุกรมวิธาน สิ่งที่โครงงานนี้เพิ่มคือการสร้างต้นแบบที่ทำงานกับ pfSense และ Suricata จริง พร้อมกลไก
ยืนยันการบังคับใช้, การยกเลิกการปิดกั้นตามเวลา, การกู้คืน IDS และการวัดเวลาของแต่ละช่วงในเส้นทางการตอบสนองอัตโนมัติในสภาพแวดล้อม
ที่ควบคุมได้ งานที่อ้างถึงไม่ได้ใช้ชุดข้อมูลหรือสภาพแวดล้อมเดียวกับโครงงานนี้ จึงไม่ได้นำผลมาเปรียบเทียบเชิงตัวเลข

## 2.12 สรุปบท

ระบบที่พัฒนาในโครงงานนี้ประกอบจากแนวคิดต่อไปนี้: firewall ที่แก้ไข table ได้ขณะทำงาน (pfSense/pf), IDS ที่ส่งออกเหตุการณ์และสถิติในรูปแบบ
JSON (Suricata/EVE), การเชื่อมโยง alert ตามแหล่งที่มาและช่วงเวลา, แบบจำลองความเสี่ยงแบบถ่วงน้ำหนักที่อ้างอิงแนวคิดจาก CVSS และ NIST
แต่ออกแบบเองสำหรับการทดลอง, การตอบสนองด้วยกฎพร้อมกลไกควบคุมความปลอดภัย และการกู้คืน IDS แบบจำกัดจำนวนครั้ง บทถัดไปอธิบายการนำ
แนวคิดเหล่านี้มาออกแบบเป็นสถาปัตยกรรมของระบบ

---

## เอกสารอ้างอิง (บทที่ 2)

[1] Netgate, "pfSense® software documentation: Introduction." [Online]. Available: https://docs.netgate.com/pfsense/en/latest/general/index.html

[2] Netgate, "Alias Features and Limitations," pfSense® software documentation. [Online]. Available: https://docs.netgate.com/pfsense/en/latest/firewall/aliases-features.html

[3] The FreeBSD Project, "pf.conf(5) — packet filter configuration file," FreeBSD 14.0-RELEASE Manual Pages. [Online]. Available: https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5&manpath=FreeBSD+14.0-RELEASE

[4] Open Information Security Foundation, "What is Suricata," Suricata User Guide, ver. 7.0.8. [Online]. Available: https://docs.suricata.io/en/suricata-7.0.8/what-is-suricata.html

[5] Open Information Security Foundation, "Eve JSON Output," Suricata User Guide, ver. 7.0.8. [Online]. Available: https://docs.suricata.io/en/suricata-7.0.8/output/eve/eve-json-output.html

[6] Open Information Security Foundation, "Eve JSON Format," Suricata User Guide, ver. 7.0.8. [Online]. Available: https://docs.suricata.io/en/suricata-7.0.8/output/eve/eve-json-format.html

[7] Open Information Security Foundation, "Meta Keywords (priority)," Suricata User Guide, ver. 7.0.8. [Online]. Available: https://docs.suricata.io/en/suricata-7.0.8/rules/meta.html

[8] FIRST, "Common Vulnerability Scoring System Version 4.0: Specification Document," ver. 1.2, Jun. 2024. [Online]. Available: https://www.first.org/cvss/v4-0/specification-document

[9] A. Nelson, S. Rekhi, M. Souppaya, and K. Scarfone, "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.

[10] P. Cichonski, T. Millar, T. Grance, and K. Scarfone, "Computer Security Incident Handling Guide," NIST SP 800-61r2, Aug. 2012, doi: 10.6028/NIST.SP.800-61r2. (superseded by [9])

[11] C. Islam, M. A. Babar, and S. Nepal, "A Multi-Vocal Review of Security Orchestration," *ACM Computing Surveys*, vol. 52, no. 2, pp. 1–45, 2019, doi: 10.1145/3305268.

[12] H. Debar and A. Wespi, "Aggregation and Correlation of Intrusion-Detection Alerts," in *Recent Advances in Intrusion Detection (RAID 2001)*, LNCS vol. 2212, Springer, 2001, pp. 85–103, doi: 10.1007/3-540-45474-8_6.

[13] F. Valeur, G. Vigna, C. Kruegel, and R. A. Kemmerer, "A Comprehensive Approach to Intrusion Detection Alert Correlation," *IEEE Transactions on Dependable and Secure Computing*, vol. 1, no. 3, pp. 146–169, 2004, doi: 10.1109/TDSC.2004.21.

[14] N. Stakhanova, S. Basu, and J. Wong, "A taxonomy of intrusion response systems," *International Journal of Information and Computer Security*, vol. 1, no. 1/2, pp. 169–184, 2007, doi: 10.1504/IJICS.2007.012248.

[15] A. Shameli-Sendi, M. Cheriet, and A. Hamou-Lhadj, "Taxonomy of intrusion risk assessment and response system," *Computers & Security*, vol. 45, pp. 1–16, 2014, doi: 10.1016/j.cose.2014.04.009.

[16] Z. Inayat, A. Gani, N. B. Anuar, M. K. Khan, and S. Anwar, "Intrusion response systems: Foundations, design, and challenges," *Journal of Network and Computer Applications*, vol. 62, pp. 53–74, 2016, doi: 10.1016/j.jnca.2015.12.006.

[17] J. Arkko, M. Cotton, and L. Vegoda, "IPv4 Address Blocks Reserved for Documentation," RFC 5737, Jan. 2010, doi: 10.17487/RFC5737.

[18] Project ITIS, "Project ITIS — Master Project Blueprint & Implementation Guide," internal project document, 2026.
