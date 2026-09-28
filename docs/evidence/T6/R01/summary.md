# T6-R01 — Auto-Unblock

- engine: 2026-09-24T16:12:39Z → 2026-09-24T16:18:02Z (logs/engine.log บรรทัด 710-772)
- input: controlled EVE injection: เหมือน T4 (5 × HIGH same src) · รอ block หมดอายุจริง 300s (ไม่แก้ expires_at)
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK VERIFIED · read-back @+10s: 198.51.100.77 อยู่ใน ITIS_BLOCK_TEST · UNBLOCK SUCCESS/VERIFIED · pf ว่างหลังจบ · FR-15 ครบ 5 จุด monotonic · BLOCK 16:12:45.308 -> UNBLOCK 16:17:45.747 · M4=1624.1 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 82, "timestamp": "2026-09-24T16:12:43.684161+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 83, "timestamp": "2026-09-24T16:12:43.684161+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 84, "timestamp": "2026-09-24T16:12:43.684161+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 85, "timestamp": "2026-09-24T16:12:43.684161+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 86, "timestamp": "2026-09-24T16:12:43.684161+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 16, "created_at": "2026-09-24T16:12:44.683975+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T16:12:43.684161+00:00", "window_end": "2026-09-24T16:12:43.684161+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[82, 83, 84, 85, 86]"}
```

### risk_assessments

```json
{"id": 16, "pattern_id": 16, "created_at": "2026-09-24T16:12:44.741216+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 16, "assessment_id": 16, "created_at": "2026-09-24T16:12:44.882807+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 21, "decision_id": 16, "timestamp": "2026-09-24T16:12:45.308336+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 22, "decision_id": 16, "timestamp": "2026-09-24T16:17:45.746615+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 16, "test_id": "T6", "t_event": "2026-09-24T16:12:43.684161+00:00", "t_detection": "2026-09-24T16:12:44.624614+00:00", "t_decision": "2026-09-24T16:12:44.683960+00:00", "t_block_cmd": "2026-09-24T16:12:44.941330+00:00", "t_block_verified": "2026-09-24T16:12:45.308300+00:00", "notes": "run=T6-R01; mode=injection; decision=BLOCK; suppressed=0"}
```
