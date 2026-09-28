# T6-R03 — Auto-Unblock

- engine: 2026-09-24T16:23:38Z → 2026-09-24T16:29:02Z (logs/engine.log บรรทัด 836-898)
- input: controlled EVE injection: เหมือน T4 (5 × HIGH same src) · รอ block หมดอายุจริง 300s (ไม่แก้ expires_at)
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK VERIFIED · read-back @+10s: 198.51.100.77 อยู่ใน ITIS_BLOCK_TEST · UNBLOCK SUCCESS/VERIFIED · pf ว่างหลังจบ · FR-15 ครบ 5 จุด monotonic · BLOCK 16:23:45.060 -> UNBLOCK 16:28:46.341 · M4=1665.7 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 92, "timestamp": "2026-09-24T16:23:43.393930+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 93, "timestamp": "2026-09-24T16:23:43.393930+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 94, "timestamp": "2026-09-24T16:23:43.393930+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 95, "timestamp": "2026-09-24T16:23:43.393930+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 96, "timestamp": "2026-09-24T16:23:43.393930+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 18, "created_at": "2026-09-24T16:23:44.384298+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T16:23:43.393930+00:00", "window_end": "2026-09-24T16:23:43.393930+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[92, 93, 94, 95, 96]"}
```

### risk_assessments

```json
{"id": 18, "pattern_id": 18, "created_at": "2026-09-24T16:23:44.472449+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 18, "assessment_id": 18, "created_at": "2026-09-24T16:23:44.534496+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 25, "decision_id": 18, "timestamp": "2026-09-24T16:23:45.059692+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 26, "decision_id": 18, "timestamp": "2026-09-24T16:28:46.340688+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 18, "test_id": "T6", "t_event": "2026-09-24T16:23:43.393930+00:00", "t_detection": "2026-09-24T16:23:44.320070+00:00", "t_decision": "2026-09-24T16:23:44.384283+00:00", "t_block_cmd": "2026-09-24T16:23:44.622926+00:00", "t_block_verified": "2026-09-24T16:23:45.059664+00:00", "notes": "run=T6-R03; mode=injection; decision=BLOCK; suppressed=0"}
```
