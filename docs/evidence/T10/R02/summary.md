# T10-R02 — False Positive Simulation

- engine: 2026-09-25T14:05:58Z → 2026-09-25T14:06:21Z (logs/engine.log บรรทัด 1688-1696)
- input: controlled EVE injection: variant a — 1 × HIGH (generator --spacing 0)
- src_ip: 198.51.100.77 · variant: a · weight_set: A
- ผลตรวจหลัง run: PASS: security_events +1 · ตารางอื่น +0 · correlation ไม่ match (ไม่ถึง min_events=5) -> ไม่มี decision/action = MONITOR/No Block ตามนิยาม 4a · active_blocks +0 · pf 0/0 · FR-15 0 แถว · HEALTHY 2 · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 1, "correlated_patterns": 0, "risk_assessments": 0, "decisions": 0, "actions": 0, "recovery_events": 0, "experiment_timestamps": 0}
```

### security_events

```json
{"id": 134, "timestamp": "2026-09-25T14:06:02.530542+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```
