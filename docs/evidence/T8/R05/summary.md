# T8-R05 — Suricata Recovery

- engine: 2026-09-24T17:18:44Z → 2026-09-24T17:20:44Z (logs/engine.log บรรทัด 1445-1471)
- input: fault injection: /usr/local/etc/rc.d/suricata.sh stop ระหว่าง engine ทำงาน (ไม่ inject EVE) · restart_command ปกติ
- src_ip: — · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: DEGRADED PROCESS_DOWN @17:18:59Z -> recovery attempt 1/3 SUCCESS (recovery_events id 5) · Suricata PID 91927->74714 (process ใหม่ ยืนยันด้วย stats uptime reset) · HEALTHY หลัง fault 7 ครั้ง · ตารางอื่น +0 · WARNING 3 (DEGRADED/recovery ตามคาด) ERROR 0 · t_fault=2026-09-24T17:18:46.021646Z

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 0, "correlated_patterns": 0, "risk_assessments": 0, "decisions": 0, "actions": 0, "recovery_events": 1, "experiment_timestamps": 0}
```

### recovery_events

```json
{"id": 5, "timestamp": "2026-09-24T17:19:12.296889+00:00", "service": "suricata", "failure_reason": "PROCESS_DOWN", "attempt": 1, "result": "SUCCESS", "error": null}
```
