# T4-R03 — Critical Pattern

- engine: 2026-09-24T15:51:48Z → 2026-09-24T15:57:12Z (logs/engine.log บรรทัด 446-509)
- input: controlled EVE injection: 5 × HIGH same src not allowlisted (generator --spacing 0) · รอ expiry 300s
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK (risk 79.5 HIGH) · BLOCK SUCCESS/VERIFIED · 300s · UNBLOCK SUCCESS/VERIFIED · pf ว่างหลังจบ · FR-15 ครบ 5 จุด monotonic · M1=945.1 M2=59.1 M3=632.2 M4=1636.4 ms · WARNING/ERROR 0 · หมายเหตุ: security_events +6 = 5 injected + 1 background alert จริงของ Suricata (id 46 · 15:56:41Z · fe80::a27:3eef:3b0a:dd1b -> ff02::2 · sid 1000001 'D' · sev 3) ไม่ match correlation ไม่กระทบ decision

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 6, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 41, "timestamp": "2026-09-24T15:51:52.969854+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 42, "timestamp": "2026-09-24T15:51:52.969854+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 43, "timestamp": "2026-09-24T15:51:52.969854+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 44, "timestamp": "2026-09-24T15:51:52.969854+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 45, "timestamp": "2026-09-24T15:51:52.969854+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 46, "timestamp": "2026-09-24T15:56:41.434537+00:00", "src_ip": "fe80:0000:0000:0000:0a27:3eef:3b0a:dd1b", "dst_ip": "ff02:0000:0000:0000:0000:0000:0000:0002", "signature": "D", "signature_id": 1000001, "severity": 3, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 8, "created_at": "2026-09-24T15:51:53.974123+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-24T15:51:52.969854+00:00", "window_end": "2026-09-24T15:51:52.969854+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[41, 42, 43, 44, 45]"}
```

### risk_assessments

```json
{"id": 8, "pattern_id": 8, "created_at": "2026-09-24T15:51:54.067262+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 8, "assessment_id": 8, "created_at": "2026-09-24T15:51:54.140887+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 10, "decision_id": 8, "timestamp": "2026-09-24T15:51:54.606308+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 11, "decision_id": 8, "timestamp": "2026-09-24T15:56:55.566492+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 8, "test_id": "T4", "t_event": "2026-09-24T15:51:52.969854+00:00", "t_detection": "2026-09-24T15:51:53.914976+00:00", "t_decision": "2026-09-24T15:51:53.974109+00:00", "t_block_cmd": "2026-09-24T15:51:54.219249+00:00", "t_block_verified": "2026-09-24T15:51:54.606284+00:00", "notes": "run=T4-R03; mode=injection; decision=BLOCK; suppressed=0"}
```
