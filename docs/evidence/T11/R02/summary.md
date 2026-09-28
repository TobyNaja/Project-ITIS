# T11-R02 — Sensitivity Analysis

- engine: 2026-09-25T14:18:18Z → 2026-09-25T14:23:38Z (logs/engine.log บรรทัด 1843-1904)
- input: controlled EVE injection: 5 × HIGH ภายใน 10 s same src (pattern เดียวกับ T4) · risk.weight_set=B ใน config.yaml ชั่วคราว (engine log ยืนยัน weight_set=B) · code d0a346d · รอ expiry
- src_ip: 198.51.100.77 · variant: — · weight_set: B
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK SUCCESS+VERIFIED · S/F/T/C 75/70/100/80 · Set B risk 80.5 CRITICAL (level เปลี่ยนจาก A) · decision เหมือน A · UNBLOCK VERIFIED · pf ว่างหลังจบ · M1=892.8 M2=78.2 M3=672.0 M4=1642.9 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 164, "timestamp": "2026-09-25T14:18:23.044239+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 165, "timestamp": "2026-09-25T14:18:23.044239+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 166, "timestamp": "2026-09-25T14:18:23.044239+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 167, "timestamp": "2026-09-25T14:18:23.044239+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 168, "timestamp": "2026-09-25T14:18:23.044239+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 27, "created_at": "2026-09-25T14:18:24.015196+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-25T14:18:23.044239+00:00", "window_end": "2026-09-25T14:18:23.044239+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[164, 165, 166, 167, 168]"}
```

### risk_assessments

```json
{"id": 27, "pattern_id": 27, "created_at": "2026-09-25T14:18:24.078473+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "B", "risk_score": 80.5, "risk_level": "CRITICAL"}
```

### decisions

```json
{"id": 27, "assessment_id": 27, "created_at": "2026-09-25T14:18:24.216306+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 43, "decision_id": 27, "timestamp": "2026-09-25T14:18:24.687183+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 44, "decision_id": 27, "timestamp": "2026-09-25T14:23:25.563423+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 27, "test_id": "T11", "t_event": "2026-09-25T14:18:23.044239+00:00", "t_detection": "2026-09-25T14:18:23.937011+00:00", "t_decision": "2026-09-25T14:18:24.015182+00:00", "t_block_cmd": "2026-09-25T14:18:24.303578+00:00", "t_block_verified": "2026-09-25T14:18:24.687159+00:00", "notes": "run=T11-R02; mode=injection; decision=BLOCK; suppressed=0"}
```
