from datetime import datetime, timedelta, timezone
from security_engine.lifecycle.block_store import BlockStore

def test_add_and_get_active_block(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    blocked_at = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
    expires_at = blocked_at + timedelta(seconds=300)
    store.add_block("192.168.2.10", blocked_at.isoformat(), expires_at.isoformat(), "RULE-001", "HIGH risk pattern")
    block = store.get_block("192.168.2.10")
    assert block is not None
    assert block["src_ip"] == "192.168.2.10"
    assert block["status"] == "ACTIVE"
    assert block["rule_id"] == "RULE-001"

def test_remove_changes_status_to_unblocked(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    now = datetime.now(timezone.utc); expires = now + timedelta(seconds=300)
    store.add_block("192.168.2.10", now.isoformat(), expires.isoformat())
    store.remove_block("192.168.2.10")
    assert store.get_block("192.168.2.10")["status"] == "EXPIRED"

def test_get_active_blocks_returns_only_active(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    now = datetime.now(timezone.utc); expires = now + timedelta(seconds=300)
    store.add_block("192.168.2.10", now.isoformat(), expires.isoformat())
    store.add_block("192.168.2.11", now.isoformat(), expires.isoformat())
    store.remove_block("192.168.2.11")
    active = store.get_active_blocks()
    assert len(active) == 1
    assert active[0]["src_ip"] == "192.168.2.10"

def test_get_expired_blocks(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    now = datetime(2026, 9, 20, 10, 5, tzinfo=timezone.utc)
    blocked_at = now - timedelta(seconds=301); expires_at = now - timedelta(seconds=1)
    store.add_block("192.168.2.10", blocked_at.isoformat(), expires_at.isoformat())
    expired = store.get_expired_blocks(now)
    assert len(expired) == 1
    assert expired[0]["src_ip"] == "192.168.2.10"

def test_unexpired_block_is_not_returned_as_expired(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    now = datetime(2026, 9, 20, 10, 5, tzinfo=timezone.utc)
    blocked_at = now - timedelta(seconds=100); expires_at = now + timedelta(seconds=200)
    store.add_block("192.168.2.10", blocked_at.isoformat(), expires_at.isoformat())
    assert store.get_expired_blocks(now) == []


def test_get_expired_blocks_handles_different_timezone_offsets(tmp_path):
    store = BlockStore(tmp_path / "test.db")

    # 17:00 +07:00 == 10:00 UTC
    expires_at = "2026-09-20T17:00:00+07:00"

    store.add_block(
        "192.168.2.10",
        "2026-09-20T16:55:00+07:00",
        expires_at,
    )

    # 10:00:01 UTC -> เลย expires ไปแล้ว 1 วินาที
    now = datetime(2026, 9, 20, 10, 0, 1, tzinfo=timezone.utc)

    expired = store.get_expired_blocks(now)

    assert len(expired) == 1
    assert expired[0]["src_ip"] == "192.168.2.10"


# ---- Phase 9.2a: REMOVE_FAILED state support ----

def _add(store, ip):
    now = datetime.now(timezone.utc)
    store.add_block(ip, now.isoformat(), (now + timedelta(seconds=300)).isoformat())


def test_mark_remove_failed_sets_status(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    _add(store, "192.168.2.10")
    store.mark_remove_failed("192.168.2.10")
    assert store.get_block("192.168.2.10")["status"] == "REMOVE_FAILED"


def test_remove_failed_is_not_active(tmp_path):
    # REMOVE_FAILED ต้องไม่ถูกนับเป็น ACTIVE (ไม่ re-block ซ้ำ)
    store = BlockStore(tmp_path / "test.db")
    _add(store, "192.168.2.10")
    store.mark_remove_failed("192.168.2.10")
    assert store.get_active_blocks() == []


def test_get_blocks_by_status_finds_remove_failed(tmp_path):
    store = BlockStore(tmp_path / "test.db")
    _add(store, "192.168.2.10")
    _add(store, "192.168.2.11")
    store.mark_remove_failed("192.168.2.10")
    failed = store.get_blocks_by_status("REMOVE_FAILED")
    assert len(failed) == 1
    assert failed[0]["src_ip"] == "192.168.2.10"


def test_retry_from_remove_failed_to_unblocked(tmp_path):
    # REMOVE_FAILED -> retry สำเร็จ -> EXPIRED
    store = BlockStore(tmp_path / "test.db")
    _add(store, "192.168.2.10")
    store.mark_remove_failed("192.168.2.10")
    store.remove_block("192.168.2.10")   # retry สำเร็จ
    assert store.get_block("192.168.2.10")["status"] == "EXPIRED"