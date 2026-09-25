# T7-R02 — Enforcement Verification

- engine: 2026-09-24T16:46:02Z → 2026-09-24T16:51:22Z (logs/engine.log บรรทัด 1087-1148)
- input: controlled EVE injection: เหมือน T4 (5 × HIGH same src) · read-back pfctl @+10s · รอ expiry
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK command SUCCESS + verify VERIFIED (engine read-back) · Layer 1 read-back (pfctl -t ITIS_BLOCK_TEST -T show @+10s) = PASS: 198.51.100.77 อยู่ใน table · Layer 2 traffic verification = NOT AVAILABLE (198.51.100.77 เป็น TEST-NET ไม่มี host จริง — ไม่ได้ยิง traffic) · UNBLOCK VERIFIED · pf ว่างหลังจบ · M3=692.1 M4=1888.3 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 112, "timestamp": "2026-09-24T16:46:06.542701+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 113, "timestamp": "2026-09-24T16:46:06.542701+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 114, "timestamp": "2026-09-24T16:46:06.542701+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 115, "timestamp": "2026-09-24T16:46:06.542701+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 116, "timestamp": "2026-09-24T16:46:06.542701+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 22, "created_at": "2026-09-24T16:46:07.738942+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T16:46:06.542701+00:00", "window_end": "2026-09-24T16:46:06.542701+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[112, 113, 114, 115, 116]"}
```

### risk_assessments

```json
{"id": 22, "pattern_id": 22, "created_at": "2026-09-24T16:46:07.886907+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 22, "assessment_id": 22, "created_at": "2026-09-24T16:46:07.945263+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 33, "decision_id": 22, "timestamp": "2026-09-24T16:46:08.431008+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 34, "decision_id": 22, "timestamp": "2026-09-24T16:51:09.650904+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 22, "test_id": "T7", "t_event": "2026-09-24T16:46:06.542701+00:00", "t_detection": "2026-09-24T16:46:07.661795+00:00", "t_decision": "2026-09-24T16:46:07.738927+00:00", "t_block_cmd": "2026-09-24T16:46:08.045287+00:00", "t_block_verified": "2026-09-24T16:46:08.430983+00:00", "notes": "run=T7-R02; mode=injection; decision=BLOCK; suppressed=0"}
```
