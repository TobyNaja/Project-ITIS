# T11-R03 — Sensitivity Analysis

- engine: 2026-09-25T14:23:48Z → 2026-09-25T14:29:07Z (logs/engine.log บรรทัด 1905-1966)
- input: controlled EVE injection: 5 × HIGH ภายใน 10 s same src (pattern เดียวกับ T4) · risk.weight_set=C ใน config.yaml ชั่วคราว (engine log ยืนยัน weight_set=C) · code d0a346d · รอ expiry
- src_ip: 198.51.100.77 · variant: — · weight_set: C
- ผลตรวจหลัง run: PASS: RULE-001 BLOCK SUCCESS+VERIFIED · S/F/T/C 75/70/100/80 · Set C risk 78.5 HIGH · decision เหมือน A · UNBLOCK VERIFIED · pf ว่างหลังจบ · M1=960.9 M2=60.2 M3=581.9 M4=1603.0 ms · WARNING/ERROR 0

## แถวใน `data/step11_experiment.db` ของ run นี้

```json
{"security_events": 5, "correlated_patterns": 1, "risk_assessments": 1, "decisions": 1, "actions": 2, "recovery_events": 0, "experiment_timestamps": 1}
```

### security_events

```json
{"id": 169, "timestamp": "2026-09-25T14:23:52.734969+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 170, "timestamp": "2026-09-25T14:23:52.734969+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 171, "timestamp": "2026-09-25T14:23:52.734969+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 172, "timestamp": "2026-09-25T14:23:52.734969+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
{"id": 173, "timestamp": "2026-09-25T14:23:52.734969+00:00", "src_ip": "198.51.100.77", "dst_ip": "198.51.100.10", "signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 1, "event_type": "alert"}
```

### correlated_patterns

```json
{"id": 28, "created_at": "2026-09-25T14:23:53.756099+00:00", "src_ip": "198.51.100.77", "window_start": "2026-09-25T14:23:52.734969+00:00", "window_end": "2026-09-25T14:23:52.734969+00:00", "event_count": 5, "max_severity": 1, "event_ids": "[169, 170, 171, 172, 173]"}
```

### risk_assessments

```json
{"id": 28, "pattern_id": 28, "created_at": "2026-09-25T14:23:53.845819+00:00", "severity_score": 75.0, "frequency_score": 70.0, "temporal_score": 100.0, "context_score": 80.0, "weight_set": "C", "risk_score": 78.5, "risk_level": "HIGH"}
```

### decisions

```json
{"id": 28, "assessment_id": 28, "created_at": "2026-09-25T14:23:53.905382+00:00", "rule_id": "RULE-001", "decision": "BLOCK", "allowlisted": 0, "reason": "[RULE-001] severity=1 (ต้อง ≤ HIGH) + 5 events (ต้อง ≥ 5) + window=0.0s (ต้อง ≤ 10s) + allowlisted=False"}
```

### actions

```json
{"id": 45, "decision_id": 28, "timestamp": "2026-09-25T14:23:54.337984+00:00", "src_ip": "198.51.100.77", "action": "BLOCK", "duration_sec": 300, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
{"id": 46, "decision_id": 28, "timestamp": "2026-09-25T14:28:55.723362+00:00", "src_ip": "198.51.100.77", "action": "UNBLOCK", "duration_sec": null, "command_result": "SUCCESS", "verify_result": "VERIFIED", "error": null}
```

### experiment_timestamps

```json
{"id": 28, "test_id": "T11", "t_event": "2026-09-25T14:23:52.734969+00:00", "t_detection": "2026-09-25T14:23:53.695872+00:00", "t_decision": "2026-09-25T14:23:53.756077+00:00", "t_block_cmd": "2026-09-25T14:23:53.962448+00:00", "t_block_verified": "2026-09-25T14:23:54.337961+00:00", "notes": "run=T11-R03; mode=injection; decision=BLOCK; suppressed=0"}
```
