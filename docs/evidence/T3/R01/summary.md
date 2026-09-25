# T3-R01 — Repeated Medium Alerts

- engine: 2026-09-24T15:36:52Z → 2026-09-24T15:37:24Z (logs/engine.log บรรทัด 250-263)
- input: controlled EVE injection: 5 × MEDIUM same src (generator --spacing 0)
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: +5 events · 1 pattern · RULE-002 ALERT (risk 69.5 HIGH) · action ALERT NOT_APPLICABLE · FR-15 1 แถว (3 จุด block NULL, monotonic) M1=887.4 M2=59.5 ms · pf ว่าง · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 1, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 6, "timestamp": "2026-09-24T15:36:57.387648+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 7, "timestamp": "2026-09-24T15:36:57.387648+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 8, "timestamp": "2026-09-24T15:36:57.387648+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 9, "timestamp": "2026-09-24T15:36:57.387648+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 10, "timestamp": "2026-09-24T15:36:57.387648+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 1, "created_at": "2026-09-24T15:36:58.334617+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T15:36:57.387648+00:00", "window_end": "2026-09-24T15:36:57.387648+00:00", "event_count": 5, "max_severity": 2, "event_ids": "[6, 7, 8, 9, 10]"}
```

### risk_assessments

```json
{"id": 1, "pattern_id": 1, "created_at": "2026-09-24T15:36:58.391463+00:00", "severity_score": 50.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 69.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 1, "assessment_id": 1, "created_at": "2026-09-24T15:36:58.451136+00:00", "rule_id": "RULE-002", "decision": "ALERT", "allowlisted": 0, "reason": "[RULE-002] severity=2 (ต้อง ≤ MEDIUM) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s)"}
```

### actions

```json
{"id": 1, "decision_id": 1, "timestamp": "2026-09-24T15:36:58.508264+00:00", "src_ip": "198.51.100.77", "action": "ALERT", "duration_sec": null, "command_result": "NOT_APPLICABLE", "verify_result": "NOT_APPLICABLE", "error": null}
```

### experiment_timestamps

```json
{"id": 1, "test_id": "T3", "t_event": "2026-09-24T15:36:57.387648+00:00", "t_detection": "2026-09-24T15:36:58.275054+00:00", "t_decision": "2026-09-24T15:36:58.334603+00:00", "t_block_cmd": null, "t_block_verified": null, "notes": "run=T3-R01; mode=injection; decision=ALERT; suppressed=0"}
```
