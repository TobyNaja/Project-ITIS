# T9-R04 — Recovery Failure

- engine: 2026-09-25T13:59:59Z → 2026-09-25T14:02:02Z (logs/engine.log บรรทัด 1596-1637)
- input: fault injection: suricata.sh stop ระหว่าง engine ทำงาน · restart_command=/usr/bin/false ชั่วคราว (คืนค่าด้วย git checkout หลังจบ T9) · POST_WAIT 120 s
- src_ip: — · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: DEGRADED PROCESS_DOWN @14:00:15Z -> attempt 1 FAIL / 2 FAIL / 3 CRITICAL (recovery_events id 15-17) · ไม่มี attempt 4 · runner latch CRITICAL 7 รอบจนจบ (ไม่มี infinite retry) · health loop ทำงานต่อ (engine ไม่ตาย) · Suricata ถูก start กลับด้วยมือ PID 63997->none->33946 + stats ใหม่ · failure_reason = PROCESS_DOWN; stderr ของ ssh (post-quantum warning) อยู่ในคอลัมน์ error ต่อจาก rc=1 — rc=1 ถูกต้อง · ตารางอื่น +0 · t_fault=2026-09-25T14:00:01.267355Z

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 0, "correlated_patterns": 0, "risk_assessments": 0, "decisions": 0, "actions": 0, "recovery_events": 3, "experiment_timestamps": 0}
```

### recovery_events

```json
{"id": 15, "timestamp": "2026-09-25T14:00:15.321306+00:00", "service": "suricata", "failure_reason": "PROCESS_DOWN", "attempt": 1, "result": "FAIL", "error": "rc=1: ** WARNING: connection is not using a post-quantum key exchange algorithm.\n** This session may be vulnerable to \"store now, decrypt later\" attacks.\n** The server may need to be upgraded. See https://openssh.com/pq.html"}
{"id": 16, "timestamp": "2026-09-25T14:00:15.552015+00:00", "service": "suricata", "failure_reason": "PROCESS_DOWN", "attempt": 2, "result": "FAIL", "error": "rc=1: ** WARNING: connection is not using a post-quantum key exchange algorithm.\n** This session may be vulnerable to \"store now, decrypt later\" attacks.\n** The server may need to be upgraded. See https://openssh.com/pq.html"}
{"id": 17, "timestamp": "2026-09-25T14:00:15.784107+00:00", "service": "suricata", "failure_reason": "PROCESS_DOWN", "attempt": 3, "result": "CRITICAL", "error": "rc=1: ** WARNING: connection is not using a post-quantum key exchange algorithm.\n** This session may be vulnerable to \"store now, decrypt later\" attacks.\n** The server may need to be upgraded. See https://openssh.com/pq.html"}
```
