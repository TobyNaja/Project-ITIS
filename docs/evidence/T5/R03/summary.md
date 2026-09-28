# T5-R03 — Allowlisted Critical Pattern

- engine: 2026-09-24T16:10:07Z → 2026-09-24T16:10:42Z (logs/engine.log บรรทัด 666-680)
- input: controlled EVE injection: 5 × HIGH same src = 192.168.2.10 (P6 allowlist ชั่วคราว) (generator --spacing 0)
- src_ip: 192.168.2.10 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-003 NO_AUTO_BLOCK allowlisted=1 · S/F/T/C=75/70/100/0 risk 67.5 HIGH (ไม่เป็น 0) · action ALERT NOT_APPLICABLE · ไม่มี BLOCK · pf ว่าง · FR-15 3 จุด block NULL monotonic · M1=931.0 M2=55.6 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 1, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 67, "timestamp": "2026-09-24T16:10:11.626091+00:00", "src_ip": "192.168.2.10", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 68, "timestamp": "2026-09-24T16:10:11.626091+00:00", "src_ip": "192.168.2.10", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 69, "timestamp": "2026-09-24T16:10:11.626091+00:00", "src_ip": "192.168.2.10", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 70, "timestamp": "2026-09-24T16:10:11.626091+00:00", "src_ip": "192.168.2.10", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 71, "timestamp": "2026-09-24T16:10:11.626091+00:00", "src_ip": "192.168.2.10", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 13, "created_at": "2026-09-24T16:10:12.612665+00:00", "src_ip": "192.168.2.10", "window_start": "2026-09-24T16:10:11.626091+00:00", "window_end": "2026-09-24T16:10:11.626091+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[67, 68, 69, 70, 71]"}
```

### risk_assessments

```json
{"id": 13, "pattern_id": 13, "created_at": "2026-09-24T16:10:12.698582+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 0.0, "weight_set": "A", "risk_score": 67.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 13, "assessment_id": 13, "created_at": "2026-09-24T16:10:12.754362+00:00", "rule_id": "RULE-003", "decision": "NO_AUTO_BLOCK", "allowlisted": 1, "reason": "[RULE-003] allowlisted=True"}
```

### actions

```json
{"id": 18, "decision_id": 13, "timestamp": "2026-09-24T16:10:12.814790+00:00", "src_ip": "192.168.2.10", "action": "ALERT", "duration_sec": null, "command_result": "NOT_APPLICABLE", "verify_result": "NOT_APPLICABLE", "error": null}
```

### experiment_timestamps

```json
{"id": 13, "test_id": "T5", "t_event": "2026-09-24T16:10:11.626091+00:00", "t_detection": "2026-09-24T16:10:12.557064+00:00", "t_decision": "2026-09-24T16:10:12.612651+00:00", "t_block_cmd": null, "t_block_verified": null, "notes": "run=T5-R03; mode=injection; decision=NO_AUTO_BLOCK; suppressed=0"}
```
