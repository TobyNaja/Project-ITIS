# T11-R01 — Sensitivity Analysis

- engine: 2026-09-25T14:12:48Z → 2026-09-25T14:18:08Z (logs/engine.log บรรทัด 1780-1842)
- input: controlled EVE injection: 5 × HIGH ภายใน 10 s same src (pattern เดียวกับ T4) · risk.weight_set=A ใน config.yaml ชั่วคราว (engine log ยืนยัน weight_set=A) · code d0a346d · รอ expiry
- src_ip: 198.51.100.77 · variant: — · weight_set: A
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK SUCCESS+VERIFIED · S/F/T/C 75/70/100/80 · Set A risk 79.5 HIGH · UNBLOCK VERIFIED · pf ว่างหลังจบ · M1=1003.6 M2=52.4 M3=599.1 M4=1655.1 ms · +1 background alert จริง (security_events id 163 sid 1000001 IPv6 fe80->ff02::2 — ไม่ใช่ input) · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 6, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 158, "timestamp": "2026-09-25T14:12:53.332768+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 159, "timestamp": "2026-09-25T14:12:53.332768+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 160, "timestamp": "2026-09-25T14:12:53.332768+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 161, "timestamp": "2026-09-25T14:12:53.332768+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 162, "timestamp": "2026-09-25T14:12:53.332768+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 163, "timestamp": "2026-09-25T14:16:21.241237+00:00", "src_ip": "fe80:0000:0000:0000:0a27:3eef:3b0a:dd1b", "dst_ip": "ff02:0000:0000:0000:0000:0000:0000:0002", "signature": "D", "signature_id": 1000001, "severity": 3, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 26, "created_at": "2026-09-25T14:12:54.388764+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-25T14:12:53.332768+00:00", "window_end": "2026-09-25T14:12:53.332768+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[158, 159, 160, 161, 162]"}
```

### risk_assessments

```json
{"id": 26, "pattern_id": 26, "created_at": "2026-09-25T14:12:54.478497+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "A", "risk_score": 79.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 26, "assessment_id": 26, "created_at": "2026-09-25T14:12:54.535773+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 41, "decision_id": 26, "timestamp": "2026-09-25T14:12:54.987848+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 42, "decision_id": 26, "timestamp": "2026-09-25T14:17:55.483695+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 26, "test_id": "T11", "t_event": "2026-09-25T14:12:53.332768+00:00", "t_detection": "2026-09-25T14:12:54.336343+00:00", "t_decision": "2026-09-25T14:12:54.388743+00:00", "t_block_cmd": "2026-09-25T14:12:54.620802+00:00", "t_block_verified": "2026-09-25T14:12:54.987823+00:00", "notes": "run=T11-R01; mode=injection; decision=BLOCK; suppressed=0"}
```
