# T7-R03 — Enforcement Verification

- engine: 2026-09-24T16:51:31Z → 2026-09-24T16:56:52Z (logs/engine.log บรรทัด 1149-1211)
- input: controlled EVE injection: เหมือน T4 (5 × HIGH same src) · read-back pfctl @+10s · รอ expiry
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK command SUCCESS + verify VERIFIED (engine read-back) · Layer 1 read-back (pfctl -t ITIS_BLOCK_TEST -T show @+10s) = PASS: 198.51.100.77 อยู่ใน table · Layer 2 traffic verification = NOT AVAILABLE (198.51.100.77 เป็น TEST-NET ไม่มี host จริง — ไม่ได้ยิง traffic) · UNBLOCK VERIFIED · pf ว่างหลังจบ · M3=603.5 M4=1609.0 ms · WARNING/ERROR 0 · หมายเหตุ: security_events +6 = 5 injected + 1 background alert จริง (id 122 · 16:56:01Z · fe80::a27:3eef:3b0a:dd1b -> ff02::2 · sid 1000001 sev 3) ไม่ match

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 6, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 117, "timestamp": "2026-09-24T16:51:36.258315+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 118, "timestamp": "2026-09-24T16:51:36.258315+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 119, "timestamp": "2026-09-24T16:51:36.258315+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 120, "timestamp": "2026-09-24T16:51:36.258315+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 121, "timestamp": "2026-09-24T16:51:36.258315+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 122, "timestamp": "2026-09-24T16:56:01.299603+00:00", "src_ip": "fe80:0000:0000:0000:0a27:3eef:3b0a:dd1b", "dst_ip": "ff02:0000:0000:0000:0000:0000:0000:0002", "signature": "D", "signature_id": 1000001, "severity": 3, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 23, "created_at": "2026-09-24T16:51:37.263859+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T16:51:36.258315+00:00", "window_end": "2026-09-24T16:51:36.258315+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[117, 118, 119, 120, 121]"}
```

### risk_assessments

```json
{"id": 23, "pattern_id": 23, "created_at": "2026-09-24T16:51:37.383670+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 23, "assessment_id": 23, "created_at": "2026-09-24T16:51:37.444351+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 35, "decision_id": 23, "timestamp": "2026-09-24T16:51:37.867367+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 36, "decision_id": 23, "timestamp": "2026-09-24T16:56:38.864948+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 23, "test_id": "T7", "t_event": "2026-09-24T16:51:36.258315+00:00", "t_detection": "2026-09-24T16:51:37.204076+00:00", "t_decision": "2026-09-24T16:51:37.263829+00:00", "t_block_cmd": "2026-09-24T16:51:37.541963+00:00", "t_block_verified": "2026-09-24T16:51:37.867341+00:00", "notes": "run=T7-R03; mode=injection; decision=BLOCK; suppressed=0"}
```
