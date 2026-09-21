"""
security_engine/lifecycle/block_store.py

Phase 9 — Persistent Block State

รับผิดชอบเฉพาะการเก็บสถานะ temporary block ลง SQLite
ไม่มีหน้าที่สั่ง pfSense และไม่มี timer

State ที่เก็บ:
- src_ip
- blocked_at
- expires_at
- status
- rule_id
- reason

Timestamp เก็บเป็น ISO 8601 (อ่านง่ายใน DB/report) แต่ต้องมี timezone เสมอ
และเวลาเทียบหมดอายุ จะ normalize เป็น UTC แล้ว compare ด้วย datetime จริง
ไม่ใช้ string comparison (กัน bug เงียบเมื่อ offset ต่างกัน)
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

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
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS active_blocks (
                    src_ip TEXT PRIMARY KEY,
                    blocked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    rule_id TEXT,
                    reason TEXT
                )
                """
            )
            conn.commit()

    def add_block(self, src_ip, blocked_at, expires_at, rule_id=None, reason=None):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO active_blocks
                (src_ip, blocked_at, expires_at, status, rule_id, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (src_ip, blocked_at, expires_at, "ACTIVE", rule_id, reason),
            )
            conn.commit()

    def remove_block(self, src_ip):
        """ทำเครื่องหมายว่า unblock สำเร็จ (verify ผ่าน) -> status UNBLOCKED"""
        self.set_status(src_ip, "UNBLOCKED")

    def mark_remove_failed(self, src_ip):
        """unblock ล้มเหลว (verify ไม่ผ่าน / SSH error) -> REMOVE_FAILED
        ยังไม่ถือว่าปลด block เพราะ pfSense อาจยัง block อยู่จริง"""
        self.set_status(src_ip, "REMOVE_FAILED")

    def set_status(self, src_ip, status):
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
                "SELECT src_ip, blocked_at, expires_at, status, rule_id, reason "
                "FROM active_blocks WHERE status = ? ORDER BY expires_at",
                (status,),
            ).fetchall()
        return [
            {"src_ip": r[0], "blocked_at": r[1], "expires_at": r[2],
             "status": r[3], "rule_id": r[4], "reason": r[5]}
            for r in rows
        ]

    def get_block(self, src_ip):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT src_ip, blocked_at, expires_at, status, rule_id, reason "
                "FROM active_blocks WHERE src_ip = ?",
                (src_ip,),
            ).fetchone()
        if row is None:
            return None
        return {
            "src_ip": row[0], "blocked_at": row[1], "expires_at": row[2],
            "status": row[3], "rule_id": row[4], "reason": row[5],
        }

    def get_active_blocks(self):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT src_ip, blocked_at, expires_at, status, rule_id, reason "
                "FROM active_blocks WHERE status = 'ACTIVE' ORDER BY expires_at"
            ).fetchall()
        return [
            {"src_ip": r[0], "blocked_at": r[1], "expires_at": r[2],
             "status": r[3], "rule_id": r[4], "reason": r[5]}
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
                "SELECT src_ip, blocked_at, expires_at, status, rule_id, reason "
                "FROM active_blocks WHERE status = 'ACTIVE' ORDER BY expires_at"
            ).fetchall()

        expired = []
        for row in rows:
            expires_at = _normalize_timestamp(row[2])
            if expires_at <= now:
                expired.append({
                    "src_ip": row[0], "blocked_at": row[1], "expires_at": row[2],
                    "status": row[3], "rule_id": row[4], "reason": row[5],
                })
        return expired