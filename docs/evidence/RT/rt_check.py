"""rt_check.py — สรุปหลักฐานของ Real-Traffic Test จาก DB (read-only)

ใช้: .venv/Scripts/python.exe docs/evidence/RT/rt_check.py data/supp_rt.db [--since 2026-09-28T09:00:00]
เปิด DB แบบ mode=ro เสมอ — ไม่เขียนอะไร
"""
import argparse
import sqlite3

ap = argparse.ArgumentParser()
ap.add_argument("db")
ap.add_argument("--since", default="0000", help="ISO8601 UTC — แสดงเฉพาะแถวหลังเวลานี้")
a = ap.parse_args()

con = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row


def show(title, sql, args=()):
    rows = con.execute(sql, args).fetchall()
    print(f"\n== {title} ({len(rows)}) ==")
    for r in rows:
        print("  " + " | ".join(f"{k}={r[k]}" for k in r.keys()))


s = a.since
show("security_events",
     "SELECT id, timestamp, src_ip, dst_ip, signature_id, severity FROM security_events "
     "WHERE timestamp >= ? ORDER BY id", (s,))
show("correlated_patterns",
     "SELECT id, created_at, src_ip, event_count, max_severity, event_ids FROM correlated_patterns "
     "WHERE created_at >= ? ORDER BY id", (s,))
show("risk_assessments",
     "SELECT r.id, r.created_at, r.risk_score, r.risk_level, r.weight_set FROM risk_assessments r "
     "WHERE r.created_at >= ? ORDER BY r.id", (s,))
show("decisions",
     "SELECT id, created_at, rule_id, decision, allowlisted, reason FROM decisions "
     "WHERE created_at >= ? ORDER BY id", (s,))
show("actions",
     "SELECT id, decision_id, timestamp, src_ip, action, duration_sec, command_result, "
     "verify_result, error FROM actions WHERE timestamp >= ? ORDER BY id", (s,))
show("active_blocks", "SELECT * FROM active_blocks ORDER BY blocked_at")
show("recovery_events",
     "SELECT * FROM recovery_events WHERE timestamp >= ? ORDER BY id", (s,))
