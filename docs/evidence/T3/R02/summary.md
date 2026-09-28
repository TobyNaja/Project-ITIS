# T3-R02 — Repeated Medium Alerts

- engine: 2026-09-24T15:37:32Z → 2026-09-24T15:38:03Z (logs/engine.log บรรทัด 264-277)
- input: controlled EVE injection: 5 × MEDIUM same src (generator --spacing 0)
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: +5 events · 1 pattern · RULE-002 ALERT (risk 69.5 HIGH) · action ALERT NOT_APPLICABLE · FR-15 1 แถว (3 จุด block NULL, monotonic) M1=833.2 M2=60.2 ms · pf ว่าง · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 1, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 11, "timestamp": "2026-09-24T15:37:36.808467+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 12, "timestamp": "2026-09-24T15:37:36.808467+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 13, "timestamp": "2026-09-24T15:37:36.808467+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 14, "timestamp": "2026-09-24T15:37:36.808467+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
{"id": 15, "timestamp": "2026-09-24T15:37:36.808467+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Suspicious inbound to mSQL port 4333", "signature_id": 2010935, "severity": 2, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 2, "created_at": "2026-09-24T15:37:37.701877+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T15:37:36.808467+00:00", "window_end": "2026-09-24T15:37:36.808467+00:00", "event_count": 5, "max_severity": 2, "event_ids": "[11, 12, 13, 14, 15]"}
```

### risk_assessments

```json
{"id": 2, "pattern_id": 2, "created_at": "2026-09-24T15:37:37.758151+00:00", "severity_score": 50.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 69.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 2, "assessment_id": 2, "created_at": "2026-09-24T15:37:37.818477+00:00", "rule_id": "RULE-002", "decision": "ALERT", "allowlisted": 0, "reason": "[RULE-002] severity=2 (ต้อง ≤ MEDIUM) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s)"}
```

### actions

```json
{"id": 2, "decision_id": 2, "timestamp": "2026-09-24T15:37:37.874865+00:00", "src_ip": "198.51.100.77", "action": "ALERT", "duration_sec": null, "command_result": "NOT_APPLICABLE", "verify_result": "NOT_APPLICABLE", "error": null}
```

### experiment_timestamps

```json
{"id": 2, "test_id": "T3", "t_event": "2026-09-24T15:37:36.808467+00:00", "t_detection": "2026-09-24T15:37:37.641653+00:00", "t_decision": "2026-09-24T15:37:37.701862+00:00", "t_block_cmd": null, "t_block_verified": null, "notes": "run=T3-R02; mode=injection; decision=ALERT; suppressed=0"}
```
