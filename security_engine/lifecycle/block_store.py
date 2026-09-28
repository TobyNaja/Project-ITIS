"""
security_engine/lifecycle/block_store.py

Phase 9 — Persistent Block State

รับผิดชอบเฉพาะการเก็บสถานะ temporary block ลง SQLite
ไม่มีหน้าที่สั่ง pfSense และไม่มี timer

State ที่เก็บ (schema กลางอยู่ที่ security_engine/storage/schema.py §3.4):
- src_ip, blocked_at, expires_at, status, action_id

rule_id / reason ไม่อยู่ที่นี่แล้ว (STEP 5D) — canonical คือ decisions.rule_id /
decisions.reason ซึ่งย้อนถึงได้ด้วย active_blocks.action_id -> actions.decision_id

status ที่ใช้:
    ACTIVE / EXPIRED / MANUALLY_REMOVED   ตาม Blueprint §3.4
    REMOVE_FAILED                          operational failure state ตาม NFR-06 (D1)

Timestamp เก็บเป็น ISO 8601 (อ่านง่ายใน DB/report) แต่ต้องมี timezone เสมอ
และเวลาเทียบหมดอายุ จะ normalize เป็น UTC แล้ว compare ด้วย datetime จริง
ไม่ใช้ string comparison (กัน bug เงียบเมื่อ offset ต่างกัน)
"""
from datetime import datetime, timezone
from pathlib import Path

from security_engine.storage.schema import (
    connect, init_db, BLOCK_STATUSES,
    STATUS_ACTIVE, STATUS_EXPIRED, STATUS_REMOVE_FAILED,
)

DEFAULT_DB_PATH = Path("data/security_engine.db")


def _normalize_timestamp(value):
    """รับ datetime หรือ ISO string (ต้องมี tz) -> คืน aware datetime ที่เป็น UTC"""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("timestamp must be datetime or ISO string")

    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")

    return dt.astimezone(timezone.utc)


class BlockStore:
    """Persistent storage สำหรับ active block lifecycle"""

    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        init_db(self.db_path)          # schema กลางทั้ง 8 ตาราง + WAL + FK

    def _connect(self):
        return connect(self.db_path)

    def add_block(self, src_ip, blocked_at, expires_at):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO active_blocks
                (src_ip, blocked_at, expires_at, status)
                VALUES (?, ?, ?, ?)
                """,
                (src_ip, blocked_at, expires_at, STATUS_ACTIVE),
            )
            conn.commit()

    def remove_block(self, src_ip):
        """unblock สำเร็จ (verify ผ่าน) -> EXPIRED ตาม Blueprint §3.4 / T6"""
        self.set_status(src_ip, STATUS_EXPIRED)

    def mark_remove_failed(self, src_ip):
        """unblock ล้มเหลว (verify ไม่ผ่าน / SSH error) -> REMOVE_FAILED
        ยังไม่ถือว่าปลด block เพราะ pfSense อาจยัง block อยู่จริง"""
        self.set_status(src_ip, STATUS_REMOVE_FAILED)

    def set_status(self, src_ip, status):
        if status not in BLOCK_STATUSES:
            raise ValueError(
                f"status ต้องเป็นหนึ่งใน {BLOCK_STATUSES} ได้ {status!r}")
        with self._connect() as conn:
            conn.execute(
                "UPDATE active_blocks SET status = ? WHERE src_ip = ?",
                (status, src_ip),
            )
            conn.commit()

    def get_blocks_by_status(self, status):
        """ดึง block ตาม status ที่ระบุ (ใช้หา REMOVE_FAILED มา retry)"""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT src_ip, blocked_at, expires_at, status, action_id "
                "FROM active_blocks WHERE status = ? ORDER BY expires_at",
                (status,),
            ).fetchall()
        return [
            {"src_ip": r[0], "blocked_at": r[1], "expires_at": r[2],
             "status": r[3], "action_id": r[4]}
            for r in rows
        ]

    def get_block(self, src_ip):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT src_ip, blocked_at, expires_at, status, action_id "
                "FROM active_blocks WHERE src_ip = ?",
                (src_ip,),
            ).fetchone()
        if row is None:
            return None
        return {
            "src_ip": row[0], "blocked_at": row[1], "expires_at": row[2],
            "status": row[3], "action_id": row[4],
        }

    def get_active_blocks(self):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT src_ip, blocked_at, expires_at, status, action_id "
                "FROM active_blocks WHERE status = ? ORDER BY expires_at",
                (STATUS_ACTIVE,),
            ).fetchall()
        return [
            {"src_ip": r[0], "blocked_at": r[1], "expires_at": r[2],
             "status": r[3], "action_id": r[4]}
            for r in rows
        ]

    def get_expired_blocks(self, now=None):
        if now is None:
            now = datetime.now(timezone.utc)
        now = _normalize_timestamp(now)

        # ดึง ACTIVE ทั้งหมดออกมา แล้ว compare ด้วย datetime จริงใน Python
        # (ไม่ให้ SQLite เทียบ string — กัน bug timezone offset)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT src_ip, blocked_at, expires_at, status, action_id "
                "FROM active_blocks WHERE status = ? ORDER BY expires_at",
                (STATUS_ACTIVE,),
            ).fetchall()

        expired = []
        for row in rows:
            expires_at = _normalize_timestamp(row[2])
            if expires_at <= now:
                expired.append({
                    "src_ip": row[0], "blocked_at": row[1], "expires_at": row[2],
                    "status": row[3], "action_id": row[4],
                })
        return expired