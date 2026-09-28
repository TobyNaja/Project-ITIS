"""
tests/test_schema.py — SQLite schema (Blueprint §3.4 + NFR-05)

ตรวจของจริงจาก SQLite ไม่ใช่ตรวจสตริง DDL:
    8 ตาราง · column/type ตาม §3.4 · FK chain ของ audit trail
    journal_mode = wal · foreign_keys = 1 · idempotent
"""
import sqlite3

import pytest

from security_engine.storage.schema import (
    connect, init_db, SCHEMA, TABLES, BLOCK_STATUSES,
    STATUS_ACTIVE, STATUS_EXPIRED, STATUS_MANUALLY_REMOVED, STATUS_REMOVE_FAILED,
)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "itis.db"
    init_db(path)
    return path


def table_names(conn):
    return sorted(r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%'"))


def columns(conn, table):
    return {r[1]: r[2] for r in conn.execute(f"PRAGMA table_info({table})")}


# ---- 1. ตารางครบ 8 ตาม §3.4 ----
def test_eight_tables_created(db):
    with connect(db) as conn:
        names = table_names(conn)
    assert len(names) == 8
    assert names == sorted(TABLES)


def test_schema_statement_count_matches_tables():
    assert len(SCHEMA) == len(TABLES) == 8


# ---- 2. column + type ของแต่ละตาราง ----
@pytest.mark.parametrize("table,expected", [
    ("security_events", {
        "id": "INTEGER", "timestamp": "TEXT", "src_ip": "TEXT", "dst_ip": "TEXT",
        "signature": "TEXT", "signature_id": "INTEGER", "severity": "INTEGER",
        "event_type": "TEXT", "raw_json": "TEXT"}),
    ("correlated_patterns", {
        "id": "INTEGER", "created_at": "TEXT", "src_ip": "TEXT",
        "window_start": "TEXT", "window_end": "TEXT", "event_count": "INTEGER",
        "max_severity": "INTEGER", "event_ids": "TEXT"}),
    ("risk_assessments", {
        "id": "INTEGER", "pattern_id": "INTEGER", "created_at": "TEXT",
        "severity_score": "REAL", "frequency_score": "REAL",
        "temporal_score": "REAL", "context_score": "REAL",
        "weight_set": "TEXT", "risk_score": "REAL", "risk_level": "TEXT"}),
    ("decisions", {
        "id": "INTEGER", "assessment_id": "INTEGER", "created_at": "TEXT",
        "rule_id": "TEXT", "decision": "TEXT", "allowlisted": "INTEGER",
        "reason": "TEXT"}),
    ("actions", {
        "id": "INTEGER", "decision_id": "INTEGER", "timestamp": "TEXT",
        "src_ip": "TEXT", "action": "TEXT", "duration_sec": "INTEGER",
        "command_result": "TEXT", "verify_result": "TEXT", "error": "TEXT"}),
    ("recovery_events", {
        "id": "INTEGER", "timestamp": "TEXT", "service": "TEXT",
        "failure_reason": "TEXT", "attempt": "INTEGER", "result": "TEXT",
        "error": "TEXT"}),
    ("experiment_timestamps", {
        "id": "INTEGER", "test_id": "TEXT", "t_event": "TEXT",
        "t_detection": "TEXT", "t_decision": "TEXT", "t_block_cmd": "TEXT",
        "t_block_verified": "TEXT", "notes": "TEXT"}),
])
def test_table_columns(db, table, expected):
    with connect(db) as conn:
        assert columns(conn, table) == expected


def test_active_blocks_columns(db):
    """§3.4 เป๊ะ — ไม่มี rule_id/reason ซ้ำ (STEP 5D)"""
    with connect(db) as conn:
        cols = columns(conn, "active_blocks")
    assert cols == {
        "src_ip": "TEXT", "blocked_at": "TEXT", "expires_at": "TEXT",
        "action_id": "INTEGER", "status": "TEXT",
    }


def test_active_blocks_primary_key_is_src_ip(db):
    with connect(db) as conn:
        pk = [r[1] for r in conn.execute("PRAGMA table_info(active_blocks)") if r[5]]
    assert pk == ["src_ip"]


# ---- 3. FK chain ของ audit trail ----
@pytest.mark.parametrize("table,column,parent,parent_column", [
    ("risk_assessments", "pattern_id", "correlated_patterns", "id"),
    ("decisions", "assessment_id", "risk_assessments", "id"),
    ("actions", "decision_id", "decisions", "id"),
    ("active_blocks", "action_id", "actions", "id"),
])
def test_foreign_keys(db, table, column, parent, parent_column):
    with connect(db) as conn:
        fks = [(r[2], r[3], r[4]) for r in
               conn.execute(f"PRAGMA foreign_key_list({table})")]
    assert (parent, column, parent_column) in fks


def test_foreign_key_is_enforced(db):
    """foreign_keys=ON ต้องมีผลจริง ไม่ใช่แค่ประกาศไว้ใน DDL"""
    with connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO risk_assessments "
                "(pattern_id, created_at, risk_score, risk_level) VALUES (?,?,?,?)",
                (999, "2026-09-22T10:00:00+00:00", 79.5, "HIGH"))


# ---- 4. PRAGMA ตาม NFR-05 ----
def test_journal_mode_is_wal(db):
    with connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_foreign_keys_pragma_on(db):
    with connect(db) as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_wal_persists_on_new_connection(db):
    # WAL ติดกับไฟล์ DB — connection ใหม่ต้องได้ wal เหมือนเดิม
    with connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    with sqlite3.connect(db) as plain:
        assert plain.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_foreign_keys_off_without_helper(db):
    """เหตุผลที่ต้องใช้ connect(): sqlite3.connect ธรรมดา foreign_keys = OFF"""
    with sqlite3.connect(db) as plain:
        assert plain.execute("PRAGMA foreign_keys").fetchone()[0] == 0


# ---- 5. idempotent + สร้างโฟลเดอร์ให้ ----
def test_init_db_is_idempotent(db):
    init_db(db)
    init_db(db)
    with connect(db) as conn:
        assert len(table_names(conn)) == 8


def test_init_db_keeps_existing_rows(db):
    with connect(db) as conn:
        conn.execute("INSERT INTO recovery_events "
                     "(timestamp, service, attempt, result) VALUES (?,?,?,?)",
                     ("2026-09-22T10:00:00+00:00", "suricata", 1, "SUCCESS"))
        conn.commit()
    init_db(db)
    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM recovery_events").fetchone()[0] == 1


def test_init_db_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "deep" / "itis.db"
    init_db(path)
    assert path.is_file()


# ---- 6. สถานะของ active_blocks ----
def test_block_statuses_cover_blueprint_and_deviation():
    assert STATUS_ACTIVE == "ACTIVE"
    assert STATUS_EXPIRED == "EXPIRED"                  # Blueprint §3.4 / T6
    assert STATUS_MANUALLY_REMOVED == "MANUALLY_REMOVED"
    assert STATUS_REMOVE_FAILED == "REMOVE_FAILED"      # deviation ตาม NFR-06 (D1)
    assert set(BLOCK_STATUSES) == {
        "ACTIVE", "EXPIRED", "MANUALLY_REMOVED", "REMOVE_FAILED"}


def test_unblocked_is_not_a_status():
    # ชื่อเดิมก่อน alignment — ต้องไม่เหลืออยู่ในระบบ
    assert "UNBLOCKED" not in BLOCK_STATUSES


# ---- 7. migration ของ DB ที่สร้างก่อน alignment (pre-freeze) ----
LEGACY_DDL = """
CREATE TABLE active_blocks (
    src_ip TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    rule_id TEXT,
    reason TEXT
)
"""

T_BLOCK = "2026-09-21T16:20:00+00:00"
T_EXPIRE = "2026-09-21T16:25:00+00:00"


@pytest.fixture
def legacy_db(tmp_path):
    """DB แบบก่อน alignment: ตารางเดียว ไม่มี action_id และใช้ status UNBLOCKED"""
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(LEGACY_DDL)
        conn.executemany(
            "INSERT INTO active_blocks "
            "(src_ip, blocked_at, expires_at, status, rule_id, reason) "
            "VALUES (?,?,?,?,?,?)",
            [("198.51.100.77", T_BLOCK, T_EXPIRE, "ACTIVE", "RULE-001", "HIGH pattern"),
             ("203.0.113.9", T_BLOCK, T_EXPIRE, "UNBLOCKED", "RULE-001", "expired ok"),
             ("198.51.100.99", T_BLOCK, T_EXPIRE, "REMOVE_FAILED", None, None)])
        conn.commit()
    return path


def test_legacy_db_gets_all_tables(legacy_db):
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        assert sorted(table_names(conn)) == sorted(TABLES)


def test_legacy_db_gains_action_id_column(legacy_db):
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        cols = columns(conn, "active_blocks")
    assert cols["action_id"] == "INTEGER"


def test_legacy_action_id_is_null_after_migration(legacy_db):
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        values = [r[0] for r in conn.execute("SELECT action_id FROM active_blocks")]
    assert values == [None, None, None]


def test_legacy_unblocked_renamed_to_expired(legacy_db):
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        rows = dict(conn.execute("SELECT src_ip, status FROM active_blocks"))
    assert rows["203.0.113.9"] == STATUS_EXPIRED
    assert "UNBLOCKED" not in rows.values()


def test_legacy_other_statuses_untouched(legacy_db):
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        rows = dict(conn.execute("SELECT src_ip, status FROM active_blocks"))
    assert rows["198.51.100.77"] == STATUS_ACTIVE
    assert rows["198.51.100.99"] == STATUS_REMOVE_FAILED


def test_legacy_rows_and_fields_preserved(legacy_db):
    """แถวและ field ที่ schema §3.4 ต้องการ ต้องอยู่ครบหลัง migrate"""
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        row = conn.execute(
            "SELECT src_ip, blocked_at, expires_at, status "
            "FROM active_blocks WHERE src_ip = ?", ("198.51.100.77",)).fetchone()
        count = conn.execute("SELECT COUNT(*) FROM active_blocks").fetchone()[0]
    assert count == 3                       # ไม่มีแถวหาย
    assert row == ("198.51.100.77", T_BLOCK, T_EXPIRE, STATUS_ACTIVE)


def test_legacy_duplicate_columns_are_dropped(legacy_db):
    """STEP 5D: rule_id/reason ถูกถอดออกจาก DB เก่าด้วย ไม่ใช่แค่ DDL ใหม่

    ค่าที่เคยอยู่ในสองคอลัมน์นี้หายไปจาก DB เก่าโดยตั้งใจ — canonical คือ
    decisions.rule_id / decisions.reason ซึ่ง dataset ก่อน alignment ไม่มีอยู่แล้ว
    """
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        cols = columns(conn, "active_blocks")
    assert "rule_id" not in cols and "reason" not in cols
    assert set(cols) == {"src_ip", "blocked_at", "expires_at", "status", "action_id"}


def test_migration_is_idempotent(legacy_db):
    init_db(legacy_db)
    init_db(legacy_db)
    init_db(legacy_db)
    with connect(legacy_db) as conn:
        cols = columns(conn, "active_blocks")
        count = conn.execute("SELECT COUNT(*) FROM active_blocks").fetchone()[0]
        statuses = sorted(r[0] for r in conn.execute("SELECT status FROM active_blocks"))
    assert list(cols).count("action_id") == 1   # ไม่เพิ่ม column ซ้ำ
    assert count == 3
    assert statuses == ["ACTIVE", "EXPIRED", "REMOVE_FAILED"]


def test_block_store_reads_migrated_legacy_db(legacy_db):
    """ของจริง: BlockStore เปิด DB เก่าแล้วต้องอ่านได้ ไม่เจอ no such column"""
    from security_engine.lifecycle.block_store import BlockStore

    store = BlockStore(legacy_db)               # __init__ เรียก init_db -> migrate
    blk = store.get_block("198.51.100.77")
    assert blk["status"] == STATUS_ACTIVE
    assert blk["action_id"] is None
    assert "rule_id" not in blk
    assert [b["src_ip"] for b in store.get_active_blocks()] == ["198.51.100.77"]
    assert [b["src_ip"] for b in store.get_blocks_by_status(STATUS_REMOVE_FAILED)] \
        == ["198.51.100.99"]


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
