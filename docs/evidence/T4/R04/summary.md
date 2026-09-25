# T4-R04 — Critical Pattern

- engine: 2026-09-24T15:57:18Z → 2026-09-24T16:02:42Z (logs/engine.log บรรทัด 510-572)
- input: controlled EVE injection: 5 × HIGH same src not allowlisted (generator --spacing 0) · รอ expiry 300s
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK (risk 79.5 HIGH) · BLOCK SUCCESS/VERIFIED · 300s · UNBLOCK SUCCESS/VERIFIED · pf ว่างหลังจบ · FR-15 ครบ 5 จุด monotonic · M1=906.4 M2=60.7 M3=546.4 M4=1513.4 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 47, "timestamp": "2026-09-24T15:57:22.794883+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 48, "timestamp": "2026-09-24T15:57:22.794883+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 49, "timestamp": "2026-09-24T15:57:22.794883+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 50, "timestamp": "2026-09-24T15:57:22.794883+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 51, "timestamp": "2026-09-24T15:57:22.794883+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 9, "created_at": "2026-09-24T15:57:23.761933+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T15:57:22.794883+00:00", "window_end": "2026-09-24T15:57:22.794883+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[47, 48, 49, 50, 51]"}
```

### risk_assessments

```json
{"id": 9, "pattern_id": 9, "created_at": "2026-09-24T15:57:23.820181+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 9, "assessment_id": 9, "created_at": "2026-09-24T15:57:23.878153+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 12, "decision_id": 9, "timestamp": "2026-09-24T15:57:24.308357+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 13, "decision_id": 9, "timestamp": "2026-09-24T16:02:25.346087+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 9, "test_id": "T4", "t_event": "2026-09-24T15:57:22.794883+00:00", "t_detection": "2026-09-24T15:57:23.701234+00:00", "t_decision": "2026-09-24T15:57:23.761909+00:00", "t_block_cmd": "2026-09-24T15:57:23.933770+00:00", "t_block_verified": "2026-09-24T15:57:24.308320+00:00", "notes": "run=T4-R04; mode=injection; decision=BLOCK; suppressed=0"}
```
