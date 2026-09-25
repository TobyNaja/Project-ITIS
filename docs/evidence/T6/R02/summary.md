# T6-R02 — Auto-Unblock

- engine: 2026-09-24T16:18:09Z → 2026-09-24T16:23:32Z (logs/engine.log บรรทัด 773-835)
- input: controlled EVE injection: เหมือน T4 (5 × HIGH same src) · รอ block หมดอายุจริง 300s (ไม่แก้ expires_at)
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK VERIFIED · read-back @+10s: 198.51.100.77 อยู่ใน ITIS_BLOCK_TEST · UNBLOCK SUCCESS/VERIFIED · pf ว่างหลังจบ · FR-15 ครบ 5 จุด monotonic · BLOCK 16:18:15.226 -> UNBLOCK 16:23:16.560 · M4=1689.4 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 87, "timestamp": "2026-09-24T16:18:13.536145+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 88, "timestamp": "2026-09-24T16:18:13.536145+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 89, "timestamp": "2026-09-24T16:18:13.536145+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 90, "timestamp": "2026-09-24T16:18:13.536145+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 91, "timestamp": "2026-09-24T16:18:13.536145+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 17, "created_at": "2026-09-24T16:18:14.571813+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T16:18:13.536145+00:00", "window_end": "2026-09-24T16:18:13.536145+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[87, 88, 89, 90, 91]"}
```

### risk_assessments

```json
{"id": 17, "pattern_id": 17, "created_at": "2026-09-24T16:18:14.666663+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 17, "assessment_id": 17, "created_at": "2026-09-24T16:18:14.725665+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 23, "decision_id": 17, "timestamp": "2026-09-24T16:18:15.225583+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 24, "decision_id": 17, "timestamp": "2026-09-24T16:23:16.560059+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 17, "test_id": "T6", "t_event": "2026-09-24T16:18:13.536145+00:00", "t_detection": "2026-09-24T16:18:14.483558+00:00", "t_decision": "2026-09-24T16:18:14.571748+00:00", "t_block_cmd": "2026-09-24T16:18:14.852023+00:00", "t_block_verified": "2026-09-24T16:18:15.225561+00:00", "notes": "run=T6-R02; mode=injection; decision=BLOCK; suppressed=0"}
```
