"""
security_engine/storage/repository.py — Audit persistence (Blueprint §3.4, FR-04/07/14)

ชั้นเดียวที่เขียน SQL — pipeline/lifecycle ห้ามเขียน SQL เอง
    security_events -> correlated_patterns -> risk_assessments -> decisions
                                                                -> actions -> active_blocks

หลักที่ล็อกไว้ (STEP 5 contract):
- `_db_id` เป็น runtime metadata ที่แปะบน event object หลัง save_security_event()
  ใช้สร้าง event_ids ของ pattern เท่านั้น **ไม่ใช่ field ของ security_events**
  และ **ห้ามเดา id จาก timestamp/IP/signature** — event ซ้ำกันได้ เดาแล้วชี้ผิดแถว
- ALERT เป็น action จริง (ไม่ใช่ skip) -> command_result/verify_result = NOT_APPLICABLE
- MONITOR ไม่สร้าง action (ไม่ใช่ response action)
- NO_AUTO_BLOCK -> actions.action = ALERT (safety override ห้าม block แต่ยังแจ้งเตือน)
  schema ไม่มี action type ชื่อ NO_AUTO_BLOCK — สถานะนั้นอยู่ใน decisions.decision

*** audit failure ≠ enforcement failure *** (NFR-06)
DB ล้ม -> log ERROR + raise AuditPersistenceError โดย **ห้ามแก้ผล enforcement ย้อนหลัง**
ถ้า pfSense block สำเร็จแล้ว firewall state จริงยังเป็น BLOCKED เสมอ ต่อให้ audit ล้ม
"""
import json
import logging
import sqlite3
from datetime import datetime, timezone

from security_engine.storage.schema import connect, init_db

log = logging.getLogger(__name__)

DB_ID_KEY = "_db_id"

# ---- actions.action (§3.4) ----
ACTION_BLOCK = "BLOCK"
ACTION_UNBLOCK = "UNBLOCK"
ACTION_ALERT = "ALERT"
VALID_ACTION_TYPES = (ACTION_BLOCK, ACTION_UNBLOCK, ACTION_ALERT)

# ---- actions.command_result / verify_result ----
COMMAND_SUCCESS = "SUCCESS"
COMMAND_FAIL = "FAIL"
VERIFY_VERIFIED = "VERIFIED"
VERIFY_FAILED = "FAILED"
NOT_APPLICABLE = "NOT_APPLICABLE"       # ALERT: ไม่มี firewall command ให้ทำ


class AuditPersistenceError(Exception):
    """เขียน/อ่าน audit trail ไม่สำเร็จ — ไม่ใช่ความล้มเหลวของ enforcement"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(value) -> str:
    """timestamp -> ISO8601 string (NFR-04: UTC ทุกจุด)"""
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return str(value)


def _json_safe(value):
    """datetime ฯลฯ -> string สำหรับ raw_json (ไม่ทำให้ payload พังเพราะ type)"""
    return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)


class AuditRepository:
    """เขียน audit chain ลง SQLite ตาม §3.4"""

    def __init__(self, db_path):
        self.db_path = db_path
        init_db(db_path)

    # ---------- infrastructure ----------
    def _write(self, sql, params, *, what):
        """execute + commit แล้วคืน lastrowid — ทุก DB error กลายเป็น AuditPersistenceError"""
        try:
            with connect(self.db_path) as conn:
                cursor = conn.execute(sql, params)
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as exc:
            log.error("audit persistence failed (%s): %s", what, exc)
            raise AuditPersistenceError(f"{what} ล้มเหลว: {exc}") from exc

    def _read(self, sql, params=(), *, what):
        try:
            with connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                return [dict(row) for row in conn.execute(sql, params)]
        except sqlite3.Error as exc:
            log.error("audit read failed (%s): %s", what, exc)
            raise AuditPersistenceError(f"{what} ล้มเหลว: {exc}") from exc

    # ---------- 1. security_events ----------
    def save_security_event(self, event) -> int:
        """บันทึก normalized event -> คืน id และแปะ `_db_id` กลับลงบน event object

        แปะบน object เดิมเพราะ CorrelationEngine เก็บ object นี้ไว้ใน window
        แล้วส่งกลับมาใน pattern.events — จะได้ไม่ต้องทำ map id(event) -> db_id เอง
        """
        raw = {k: v for k, v in event.items() if k != DB_ID_KEY}
        event_id = self._write(
            "INSERT INTO security_events "
            "(timestamp, src_ip, dst_ip, signature, signature_id, severity, "
            " event_type, raw_json) VALUES (?,?,?,?,?,?,?,?)",
            (_iso(event.get("timestamp")),
             event.get("src_ip"),
             event.get("dest_ip") or event.get("dst_ip"),
             event.get("signature"),
             event.get("signature_id"),
             event.get("severity"),
             event.get("event_type", "alert"),
             _json_safe(raw)),
            what="save_security_event")
        event[DB_ID_KEY] = event_id
        return event_id

    # ---------- 2. correlated_patterns ----------
    def save_correlated_pattern(self, pattern, created_at=None) -> int:
        """event_ids มาจาก `_db_id` ของ event ในหน้าต่างเท่านั้น

        event ที่ไม่มี `_db_id` = ยังไม่ถูกบันทึก -> error ทันที ไม่เดา id
        """
        event_ids = []
        for index, event in enumerate(pattern.events):
            db_id = event.get(DB_ID_KEY) if hasattr(event, "get") else None
            if db_id is None:
                raise AuditPersistenceError(
                    f"pattern ของ {pattern.src_ip}: event[{index}] ไม่มี {DB_ID_KEY} "
                    "(ต้อง save_security_event ก่อน) — ห้ามเดา id จากเนื้อ event")
            event_ids.append(db_id)

        return self._write(
            "INSERT INTO correlated_patterns "
            "(created_at, src_ip, window_start, window_end, event_count, "
            " max_severity, event_ids) VALUES (?,?,?,?,?,?,?)",
            (_iso(created_at), pattern.src_ip,
             _iso(pattern.window_start), _iso(pattern.window_end),
             pattern.event_count, pattern.max_severity,
             json.dumps(event_ids)),
            what="save_correlated_pattern")

    # ---------- 3. risk_assessments ----------
    def save_risk_assessment(self, pattern_id, risk, created_at=None) -> int:
        """field ของ RiskResult ตรงกับ schema อยู่แล้ว — ไม่ต้องแปลงชื่อ"""
        return self._write(
            "INSERT INTO risk_assessments "
            "(pattern_id, created_at, severity_score, frequency_score, "
            " temporal_score, context_score, weight_set, risk_score, risk_level) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (pattern_id, _iso(created_at),
             risk.severity_score, risk.frequency_score,
             risk.temporal_score, risk.context_score,
             risk.weight_set, risk.risk_score, risk.risk_level),
            what="save_risk_assessment")

    # ---------- 4. decisions ----------
    def save_decision(self, assessment_id, decision, *, allowlisted,
                      created_at=None) -> int:
        """บันทึกทุก Decision ที่ Rule Engine สร้าง (BLOCK/ALERT/NO_AUTO_BLOCK/MONITOR)

        allowlisted ต้องส่งมาจากผู้เรียก (pipeline รู้จาก SourceContext) ไม่ derive
        จาก rule_id เพราะกฎอาจเปลี่ยนใน rules.yaml
        """
        return self._write(
            "INSERT INTO decisions "
            "(assessment_id, created_at, rule_id, decision, allowlisted, reason) "
            "VALUES (?,?,?,?,?,?)",
            (assessment_id, _iso(created_at),
             getattr(decision, "rule_id", None),
             decision.action,
             1 if allowlisted else 0,
             decision.reason),
            what="save_decision")

    # ---------- 5. actions ----------
    def save_action(self, decision_id, *, action, src_ip, duration_sec=None,
                    command_result=None, verify_result=None, error=None,
                    timestamp=None) -> int:
        if action not in VALID_ACTION_TYPES:
            raise AuditPersistenceError(
                f"actions.action ต้องเป็นหนึ่งใน {VALID_ACTION_TYPES} ได้ {action!r}")
        return self._write(
            "INSERT INTO actions "
            "(decision_id, timestamp, src_ip, action, duration_sec, "
            " command_result, verify_result, error) VALUES (?,?,?,?,?,?,?,?)",
            (decision_id, _iso(timestamp), src_ip, action, duration_sec,
             command_result, verify_result, error),
            what="save_action")

    def save_enforcement_action(self, decision_id, result, *, duration_sec=None,
                                error=None, timestamp=None) -> int:
        """จาก EnforcementResult ของ enforcer (add -> BLOCK, remove -> UNBLOCK)

        command success ≠ enforcement success — เก็บแยกสองคอลัมน์ตาม FR-08
        """
        action = ACTION_BLOCK if result.action == "add" else ACTION_UNBLOCK
        return self.save_action(
            decision_id,
            action=action,
            src_ip=result.ip,
            duration_sec=duration_sec,
            command_result=COMMAND_SUCCESS if result.command_ok else COMMAND_FAIL,
            verify_result=VERIFY_VERIFIED if result.verified else VERIFY_FAILED,
            error=error,
            timestamp=timestamp)

    def save_alert_action(self, decision_id, src_ip, *, timestamp=None) -> int:
        """ALERT ไม่มี firewall command -> NOT_APPLICABLE (ไม่ใช่ SKIPPED)"""
        return self.save_action(
            decision_id,
            action=ACTION_ALERT,
            src_ip=src_ip,
            duration_sec=None,
            command_result=NOT_APPLICABLE,
            verify_result=NOT_APPLICABLE,
            error=None,
            timestamp=timestamp)

    # ---------- 6. recovery_events (FR-13 / M10) ----------
    def save_recovery_event(self, *, service, attempt, result,
                            failure_reason=None, error=None, timestamp=None) -> int:
        """บันทึกทุก attempt ของการกู้ service (§3.4 recovery_events)

        result: SUCCESS / FAIL / CRITICAL
        failure_reason: PROCESS_DOWN / EVE_STALE (หลายสาเหตุคั่นด้วย ';')
        """
        return self._write(
            "INSERT INTO recovery_events "
            "(timestamp, service, failure_reason, attempt, result, error) "
            "VALUES (?,?,?,?,?,?)",
            (_iso(timestamp), service, failure_reason, attempt, result, error),
            what="save_recovery_event")

    def get_recovery_events(self, service=None):
        if service is None:
            return self._read("SELECT * FROM recovery_events ORDER BY id",
                              what="get_recovery_events")
        return self._read("SELECT * FROM recovery_events WHERE service = ? ORDER BY id",
                          (service,), what="get_recovery_events")

    # ---------- 7. active_blocks link ----------
    def link_active_block_action(self, src_ip, action_id) -> None:
        """ผูก active_blocks ที่ lifecycle สร้างไว้เข้ากับ actions.id

        lifecycle เขียน active_blocks เองภายใน block() (ห้ามแก้ใน STEP นี้)
        จึงมีช่วงสั้น ๆ ที่ action_id เป็น NULL ก่อนถูก link — เป็น transient state
        ที่ยอมรับไว้ใน STEP 5 (ดู docs/blueprint-alignment-plan.md)
        """
        try:
            with connect(self.db_path) as conn:
                cursor = conn.execute(
                    "UPDATE active_blocks SET action_id = ? WHERE src_ip = ?",
                    (action_id, src_ip))
                conn.commit()
        except sqlite3.Error as exc:
            log.error("audit persistence failed (link_active_block_action): %s", exc)
            raise AuditPersistenceError(
                f"link_active_block_action ล้มเหลว: {exc}") from exc
        if cursor.rowcount == 0:
            raise AuditPersistenceError(
                f"ไม่พบ active_blocks ของ {src_ip} สำหรับผูก action_id={action_id}")

    # ---------- read helpers (audit / test) ----------
    def get_audit_chain(self, src_ip):
        """ไล่ย้อน active_blocks -> actions -> decisions -> risk_assessments
        -> correlated_patterns ด้วย FK จริง (ใช้พิสูจน์ chain ตาม §3.4)"""
        rows = self._read(
            "SELECT ab.src_ip, ab.status, ab.action_id, "
            "       a.id AS action_row_id, a.action, a.command_result, "
            "       a.verify_result, a.duration_sec, "
            "       d.id AS decision_id, d.decision, d.rule_id, d.allowlisted, d.reason, "
            "       r.id AS assessment_id, r.risk_score, r.risk_level, r.weight_set, "
            "       r.severity_score, r.frequency_score, r.temporal_score, r.context_score, "
            "       p.id AS pattern_id, p.event_count, p.max_severity, p.event_ids "
            "FROM active_blocks ab "
            "JOIN actions a ON a.id = ab.action_id "
            "JOIN decisions d ON d.id = a.decision_id "
            "JOIN risk_assessments r ON r.id = d.assessment_id "
            "JOIN correlated_patterns p ON p.id = r.pattern_id "
            "WHERE ab.src_ip = ?", (src_ip,), what="get_audit_chain")
        return rows[0] if rows else None

    def get_decision(self, decision_id):
        rows = self._read("SELECT * FROM decisions WHERE id = ?",
                          (decision_id,), what="get_decision")
        return rows[0] if rows else None

    def get_action(self, action_id):
        rows = self._read("SELECT * FROM actions WHERE id = ?",
                          (action_id,), what="get_action")
        return rows[0] if rows else None

    def get_security_events(self, ids):
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        return self._read(
            f"SELECT * FROM security_events WHERE id IN ({placeholders}) ORDER BY id",
            tuple(ids), what="get_security_events")
