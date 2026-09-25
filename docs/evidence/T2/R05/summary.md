# T2-R05 — Single Medium Alert

- engine: 2026-09-24T15:35:42Z → 2026-09-24T15:36:13Z (logs/engine.log บรรทัด 240-249)
- input: controlled EVE injection: 1 × MEDIUM (generator --spacing 0)
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: security_events +1 · ตารางอื่น +0 · correlation ไม่ match · FR-15 0 แถว · pf ว่าง · HEALTHY 3 · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 1, "correlated_patterns": 0, "risk_assessments": 0, "decisions": 0, "actions": 0, "recovery_events": 0, "experiment_timestamps": 0}
```

### security_events

```json
{"id": 5, "timestamp": "2026-09-24T15:35:46.793602+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
```
