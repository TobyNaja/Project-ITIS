# T10-R08 — False Positive Simulation

- engine: 2026-09-25T14:09:23Z → 2026-09-25T14:09:41Z (logs/engine.log บรรทัด 1746-1756)
- input: controlled EVE injection: variant b — 4 × HIGH ภายใน 10 s same src (generator --spacing 0)
- src_ip: 198.51.100.77 · variant: b · weight_set: A
- ผลตรวจหลัง run: PASS: security_events +4 · ตารางอื่น +0 · correlation ไม่ match (4 < min_events=5) -> ไม่มี decision/action = MONITOR/No Block ตามนิยาม 4a · active_blocks +0 · pf 0/0 · FR-15 0 แถว · HEALTHY 2 · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 4, "correlated_patterns": 0, "risk_assessments": 0, "decisions": 0, "actions": 0, "recovery_events": 0, "experiment_timestamps": 0}
```

### security_events

```json
{"id": 146, "timestamp": "2026-09-25T14:09:27.824069+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 147, "timestamp": "2026-09-25T14:09:27.824069+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 148, "timestamp": "2026-09-25T14:09:27.824069+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 149, "timestamp": "2026-09-25T14:09:27.824069+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```
