"""
security_engine/storage/schema.py — SQLite schema (Blueprint §3.4)

source of truth เดียวของ DDL — โมดูลอื่นเปิด DB ผ่าน connect()/init_db() เท่านั้น
จะได้ไม่มีใครสร้างตารางเองคนละแบบ

audit chain ที่ FK บังคับไว้ (§3.4):
    security_events -> correlated_patterns -> risk_assessments -> decisions
                                                                   -> actions -> active_blocks

NFR-05 (SQLite Safety):
    - PRAGMA journal_mode=WAL      ตั้งครั้งเดียว ติดอยู่กับไฟล์ DB
    - PRAGMA foreign_keys=ON       ต้องตั้ง **ทุก connection** (SQLite default = OFF)
    - parameterized query เท่านั้น (ไม่มี string format SQL ในโปรเจกต์นี้)

*** ไฟล์นี้ไม่รู้จัก business logic *** — แค่เปิด/สร้างโครงเก็บข้อมูล
"""
import sqlite3
from pathlib import Path

# ---- สถานะของ active_blocks ----
# ACTIVE / EXPIRED / MANUALLY_REMOVED = ตาม Blueprint §3.4
# REMOVE_FAILED = operational failure state ที่เพิ่มตาม NFR-06 (ดู alignment plan D1)
STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_MANUALLY_REMOVED = "MANUALLY_REMOVED"
STATUS_REMOVE_FAILED = "REMOVE_FAILED"
BLOCK_STATUSES = (STATUS_ACTIVE, STATUS_EXPIRED,
                  STATUS_MANUALLY_REMOVED, STATUS_REMOVE_FAILED)

TABLES = (
    "security_events",
    "correlated_patterns",
    "risk_assessments",
    "decisions",
    "actions",
    "active_blocks",
    "recovery_events",
    "experiment_timestamps",
)

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,            -- ISO8601 UTC (NFR-04)
        src_ip TEXT NOT NULL,
        dst_ip TEXT,
        signature TEXT,
        signature_id INTEGER,
        severity INTEGER,                   -- Suricata: 1=High, 2=Medium, 3=Low
        event_type TEXT,
        raw_json TEXT                       -- เก็บ raw ไว้เป็นหลักฐาน
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS correlated_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        window_start TEXT NOT NULL,
        window_end TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        max_severity INTEGER NOT NULL,      -- severity ที่รุนแรงที่สุด (เลขน้อยสุด)
        event_ids TEXT NOT NULL             -- JSON array ของ security_events.id
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_id INTEGER NOT NULL REFERENCES correlated_patterns(id),
        created_at TEXT NOT NULL,
        severity_score REAL,
        frequency_score REAL,
        temporal_score REAL,
        context_score REAL,
        weight_set TEXT NOT NULL DEFAULT 'A',
        risk_score REAL NOT NULL,           -- 0-100
        risk_level TEXT NOT NULL            -- LOW/MEDIUM/HIGH/CRITICAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessment_id INTEGER NOT NULL REFERENCES risk_assessments(id),
        created_at TEXT NOT NULL,
        rule_id TEXT,                       -- 'RULE-001' หรือ NULL = default
        decision TEXT NOT NULL,             -- MONITOR/ALERT/BLOCK/NO_AUTO_BLOCK
        allowlisted INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL                -- explainable (FR-14)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        decision_id INTEGER REFERENCES decisions(id),
        timestamp TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        action TEXT NOT NULL,               -- BLOCK/UNBLOCK/ALERT
        duration_sec INTEGER,
        command_result TEXT,                -- SUCCESS/FAIL
        verify_result TEXT,                 -- VERIFIED/FAILED/SKIPPED
        error TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS active_blocks (
        src_ip TEXT PRIMARY KEY,
        blocked_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        action_id INTEGER REFERENCES actions(id),
        status TEXT NOT NULL,               -- ACTIVE/EXPIRED/MANUALLY_REMOVED/REMOVE_FAILED
        rule_id TEXT,                       -- ชั่วคราว: จะย้ายไป decisions ใน STEP 5
        reason TEXT                         -- ชั่วคราว: จะย้ายไป decisions ใน STEP 5
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS recovery_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        service TEXT NOT NULL,              -- 'suricata'
        failure_reason TEXT,                -- PROCESS_DOWN/EVE_STALE
        attempt INTEGER NOT NULL,
        result TEXT NOT NULL,               -- SUCCESS/FAIL/CRITICAL
        error TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS experiment_timestamps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_id TEXT NOT NULL,              -- T1..T11
        t_event TEXT,
        t_detection TEXT,
        t_decision TEXT,
        t_block_cmd TEXT,
        t_block_verified TEXT,
        notes TEXT
    )
    """,
)


def connect(db_path) -> sqlite3.Connection:
    """เปิด connection พร้อม PRAGMA ที่ NFR-05 กำหนด

    foreign_keys ต้องตั้งใหม่ทุก connection (SQLite default OFF)
    ส่วน journal_mode=WAL ติดกับไฟล์ DB — ตั้งซ้ำไม่เสียหาย
    """
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _column_names(conn, table):
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]


def _migrate_active_blocks(conn) -> None:
    """migration ขั้นต่ำสำหรับ DB ที่สร้างก่อน blueprint alignment (pre-freeze)

    `CREATE TABLE IF NOT EXISTS` ไม่แตะตารางที่มีอยู่แล้ว DB เก่าจึงไม่มี action_id
    และยังใช้ status ชื่อเดิม — ต้องเติมให้ ไม่งั้น SELECT จะพังด้วย
    `no such column: action_id`

    *** ไม่ลบหรือเขียนทับข้อมูลเดิม *** — เติม column (ค่า NULL) และ rename สถานะเท่านั้น
    ต้องเรียก **หลัง** สร้างตาราง actions แล้ว เพราะ action_id อ้างถึง actions(id)
    """
    columns = _column_names(conn, "active_blocks")
    if not columns:                     # ยังไม่มีตาราง = DB ใหม่ ไม่ต้อง migrate
        return

    if "action_id" not in columns:
        conn.execute(
            "ALTER TABLE active_blocks "
            "ADD COLUMN action_id INTEGER REFERENCES actions(id)")

    # D2: UNBLOCKED (ชื่อก่อน alignment) -> EXPIRED ตาม Blueprint §3.4 / T6
    conn.execute("UPDATE active_blocks SET status = ? WHERE status = ?",
                 (STATUS_EXPIRED, "UNBLOCKED"))


def init_db(db_path) -> None:
    """สร้างโฟลเดอร์ + ตารางทั้ง 8 ถ้ายังไม่มี แล้ว migrate ของเก่า (idempotent)"""
    path = Path(db_path)
    if path.parent and str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        for statement in SCHEMA:        # actions ถูกสร้างก่อน active_blocks อยู่แล้ว
            conn.execute(statement)
        _migrate_active_blocks(conn)
        conn.commit()
