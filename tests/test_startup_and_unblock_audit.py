"""
tests/test_startup_and_unblock_audit.py — STEP 6D

6D-1 Startup reconcile (FR-10 Restart Resilience)
    production caller ต้องเรียก reconcile() จริงก่อน runner.start()
        ACTIVE ที่หมดอายุระหว่าง process ดับ -> ปลดทันที
        ACTIVE ที่ยังไม่หมดอายุ             -> คงไว้
        REMOVE_FAILED ที่ค้าง               -> retry

6D-2 UNBLOCK audit (§3.4 / M9)
    lifecycle ปลด block -> actions.action = UNBLOCK พร้อม command/verify result
        ผูกกับ decision เดิมที่สั่ง BLOCK ผ่าน actions.decision_id
        *** active_blocks.action_id ยังชี้ BLOCK action เดิม ***
        ไม่เพิ่มคอลัมน์ใหม่ใน schema §3.4
"""
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

import run_phase4
from security_engine.correlation.engine import CorrelationEngine
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
from security_engine.lifecycle.block_store import BlockStore
from security_engine.pipeline import SecurityPipeline
from security_engine.policy.rule_engine import Decision, RuleEngine, BLOCK
from security_engine.policy.rules_config import load_rules
from security_engine.storage.repository import (
    AuditRepository, ACTION_BLOCK, ACTION_UNBLOCK,
    COMMAND_SUCCESS, COMMAND_FAIL, VERIFY_VERIFIED, VERIFY_FAILED,
)
from security_engine.storage.schema import (
    connect, STATUS_ACTIVE, STATUS_EXPIRED, STATUS_REMOVE_FAILED,
)

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)
IP = "198.51.100.77"
OTHER = "203.0.113.5"


class FakeResult:
    def __init__(self, action, ip, ok=True):
        self.action = action
        self.ip = ip
        self.command_ok = ok
        self.verified = ok
        self.status = "ENFORCED" if ok else "FAILED"

    @property
    def success(self):
        return self.command_ok and self.verified


class FakeEnforcer:
    def __init__(self, add_ok=True, remove_ok=True):
        self.add_ok = add_ok
        self.remove_ok = remove_ok
        self.added = []
        self.removed = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeResult("add", ip, self.add_ok)

    def remove_block(self, ip):
        self.removed.append(ip)
        return FakeResult("remove", ip, self.remove_ok)

    def is_blocked(self, ip):
        return ip in self.added and ip not in self.removed


class FakeClock:
    def __init__(self, start):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t = self.t + timedelta(seconds=seconds)


def eve(severity=1, offset=0.0, src=IP):
    ts = (T0 + timedelta(seconds=offset)).isoformat()
    return {"src_ip": src, "dest_ip": "192.0.2.10", "severity": severity,
            "signature": "ET TEST", "signature_id": 2001219,
            "event_type": "alert", "timestamp": ts, "received_at": ts}


def rows(db_path, table):
    with connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def build_stack(tmp_path, remove_ok=True, duration=300):
    """pipeline + lifecycle + repository บน DB ไฟล์เดียว"""
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    store = BlockStore(db)
    enforcer = FakeEnforcer(remove_ok=remove_ok)
    clock = FakeClock(T0)
    mgr = BlockLifecycleManager(enforcer, store, clock=clock, repository=repo)
    pipe = SecurityPipeline(CorrelationEngine(window_seconds=10, min_events=5),
                            RuleEngine(load_rules()), mgr,
                            lock=threading.Lock(), repository=repo)
    return pipe, repo, store, enforcer, clock, mgr, db


def feed_block(pipe, count=5):
    trace = None
    for i in range(count):
        trace = pipe.process(eve(offset=i * 0.5))
    return trace


# =====================================================================
# 6D-1  startup reconcile
# =====================================================================
class _SpyRunner:
    """จับลำดับ: reconcile ต้องมาก่อน start"""
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.calls = []

    def start(self):
        self.calls.append("start")

    def stop(self, *args, **kwargs):
        self.calls.append("stop")

    def is_running(self):
        return False


class _SpyLifecycle:
    def __init__(self, calls):
        self.calls = calls

    def reconcile(self, now=None):
        self.calls.append("reconcile")
        return []


def test_run_calls_reconcile_before_runner_start():
    """FR-10: production caller ต้องเรียก reconcile() จริง ไม่ใช่มีแค่ method"""
    calls = []
    lifecycle = _SpyLifecycle(calls)
    runner = _SpyRunner(lifecycle)
    runner.calls = calls                      # ใช้ list เดียวกันเพื่อดูลำดับ

    class _Pipe:
        def process(self, event):
            return {"src_ip": "x", "correlation_matched": False, "decision": None}

    run_phase4.run(_Pipe(), runner, [])

    assert calls[0] == "reconcile"
    assert calls[1] == "start"
    assert calls[-1] == "stop"


def test_reconcile_unblocks_expired_after_restart(tmp_path):
    """block หมดอายุระหว่าง process ดับ -> manager ตัวใหม่ปลดให้ตอน startup"""
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    clock = FakeClock(T0)

    enf1 = FakeEnforcer()
    mgr1 = BlockLifecycleManager(enf1, BlockStore(db), clock=clock, repository=repo)
    mgr1.block(Decision(action=BLOCK, rule_id="RULE-001", src_ip=IP,
                        reason="r", block_duration=300))
    assert rows(db, "active_blocks")[0]["status"] == STATUS_ACTIVE

    # ...process ดับ... เวลาผ่านไปเกินหมดอายุ
    clock.advance(301)

    enf2 = FakeEnforcer()
    mgr2 = BlockLifecycleManager(enf2, BlockStore(db), clock=clock, repository=repo)
    mgr2.reconcile()

    assert enf2.removed == [IP]
    assert rows(db, "active_blocks")[0]["status"] == STATUS_EXPIRED


def test_reconcile_retains_unexpired_block(tmp_path):
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    clock = FakeClock(T0)
    enf = FakeEnforcer()
    mgr = BlockLifecycleManager(enf, BlockStore(db), clock=clock, repository=repo)
    mgr.block(Decision(action=BLOCK, rule_id="RULE-001", src_ip=IP,
                       reason="r", block_duration=300))

    clock.advance(100)                        # ยังไม่หมดอายุ
    BlockLifecycleManager(FakeEnforcer(), BlockStore(db), clock=clock,
                          repository=repo).reconcile()

    assert rows(db, "active_blocks")[0]["status"] == STATUS_ACTIVE


def test_reconcile_retries_remove_failed(tmp_path):
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    clock = FakeClock(T0)
    enf = FakeEnforcer(remove_ok=False)
    mgr = BlockLifecycleManager(enf, BlockStore(db), clock=clock, repository=repo)
    mgr.block(Decision(action=BLOCK, rule_id="RULE-001", src_ip=IP,
                       reason="r", block_duration=10))
    clock.advance(11)
    mgr.expire_due()
    assert rows(db, "active_blocks")[0]["status"] == STATUS_REMOVE_FAILED

    # restart: manager ตัวใหม่ (counter เริ่มใหม่) + pfSense กลับมาปกติ
    enf2 = FakeEnforcer(remove_ok=True)
    BlockLifecycleManager(enf2, BlockStore(db), clock=clock,
                          repository=repo).reconcile()

    assert enf2.removed == [IP]
    assert rows(db, "active_blocks")[0]["status"] == STATUS_EXPIRED


def test_build_pipeline_wires_repository_and_lifecycle(tmp_path, monkeypatch):
    """production wiring: lifecycle กับ pipeline ต้องใช้ repository ตัวเดียวกัน"""
    monkeypatch.chdir(run_phase4.__file__.rsplit("run_phase4.py", 1)[0])
    pipeline, runner, _ = run_phase4.build_pipeline(
        db_path=str(tmp_path / "wire.db"),
        enforcer=FakeEnforcer(), correlator=object())

    assert pipeline.repository is not None
    assert runner.lifecycle.repository is pipeline.repository


# =====================================================================
# 6D-2  UNBLOCK audit
# =====================================================================
def test_successful_unblock_is_recorded(tmp_path):
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path)
    feed_block(pipe)
    clock.advance(301)

    mgr.expire_due()

    actions = rows(db, "actions")
    assert [a["action"] for a in actions] == [ACTION_BLOCK, ACTION_UNBLOCK]
    unblock = actions[1]
    assert unblock["src_ip"] == IP
    assert unblock["command_result"] == COMMAND_SUCCESS
    assert unblock["verify_result"] == VERIFY_VERIFIED
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


def test_unblock_links_to_same_decision_as_block(tmp_path):
    """ผูกผ่าน actions.decision_id — ไม่ต้องเพิ่มคอลัมน์ใหม่ใน schema"""
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path)
    feed_block(pipe)
    clock.advance(301)
    mgr.expire_due()

    block_action, unblock_action = rows(db, "actions")
    assert unblock_action["decision_id"] == block_action["decision_id"]
    assert unblock_action["decision_id"] == rows(db, "decisions")[0]["id"]


def test_active_block_action_id_still_points_to_block_action(tmp_path):
    """active_blocks.action_id = action ที่ทำให้ block เกิด (BLOCK) ไม่ใช่ UNBLOCK"""
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path)
    feed_block(pipe)
    block_action_id = rows(db, "active_blocks")[0]["action_id"]
    clock.advance(301)
    mgr.expire_due()

    after = rows(db, "active_blocks")[0]
    assert after["action_id"] == block_action_id
    assert rows(db, "actions")[0]["id"] == block_action_id
    assert rows(db, "actions")[0]["action"] == ACTION_BLOCK


def test_failed_unblock_is_recorded_as_failure(tmp_path):
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path, remove_ok=False)
    feed_block(pipe)
    clock.advance(301)

    mgr.expire_due()

    unblock = rows(db, "actions")[1]
    assert unblock["action"] == ACTION_UNBLOCK
    assert unblock["command_result"] == COMMAND_FAIL
    assert unblock["verify_result"] == VERIFY_FAILED
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED


def test_every_removal_attempt_is_audited(tmp_path):
    """M9 ต้องนับได้: ทุกครั้งที่พยายามปลด ต้องมี action row"""
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path, remove_ok=False)
    feed_block(pipe)
    clock.advance(301)

    mgr.expire_due()          # attempt 1
    mgr.expire_due()          # attempt 2
    enforcer.remove_ok = True
    mgr.expire_due()          # attempt 3 -> สำเร็จ

    actions = rows(db, "actions")
    unblocks = [a for a in actions if a["action"] == ACTION_UNBLOCK]
    assert len(unblocks) == 3
    assert [a["command_result"] for a in unblocks] == \
        [COMMAND_FAIL, COMMAND_FAIL, COMMAND_SUCCESS]
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


def test_m9_countable_from_db(tmp_path):
    """นับ auto-unblock success rate จาก DB ได้จริง (ไม่ต้องพึ่ง JSONL)"""
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path)
    feed_block(pipe)
    clock.advance(301)
    mgr.expire_due()

    with connect(db) as conn:
        total, verified = conn.execute(
            "SELECT COUNT(*), SUM(CASE WHEN verify_result = ? THEN 1 ELSE 0 END) "
            "FROM actions WHERE action = ?",
            (VERIFY_VERIFIED, ACTION_UNBLOCK)).fetchone()
    assert (total, verified) == (1, 1)


def test_lifecycle_without_repository_still_works(tmp_path):
    """manager ที่ไม่มี repository ต้องทำงานได้ (unit test เดิมไม่พัง)"""
    store = BlockStore(tmp_path / "plain.db")
    enforcer = FakeEnforcer()
    clock = FakeClock(T0)
    mgr = BlockLifecycleManager(enforcer, store, clock=clock)   # ไม่มี repository

    mgr.block(Decision(action=BLOCK, rule_id="RULE-001", src_ip=IP,
                       reason="r", block_duration=10))
    clock.advance(11)
    mgr.expire_due()

    assert store.get_block(IP)["status"] == STATUS_EXPIRED
    assert rows(tmp_path / "plain.db", "actions") == []


def test_unblock_without_block_action_id_is_still_recorded(tmp_path):
    """block ที่ไม่มี action_id (เช่น DB เก่า) -> UNBLOCK ยังถูกบันทึก decision_id=NULL"""
    db = tmp_path / "itis.db"
    repo = AuditRepository(db)
    store = BlockStore(db)
    clock = FakeClock(T0)
    enforcer = FakeEnforcer()
    mgr = BlockLifecycleManager(enforcer, store, clock=clock, repository=repo)

    store.add_block(IP, T0.isoformat(), (T0 + timedelta(seconds=10)).isoformat())
    clock.advance(11)
    mgr.expire_due()

    unblock = rows(db, "actions")[0]
    assert unblock["action"] == ACTION_UNBLOCK
    assert unblock["decision_id"] is None
    assert store.get_block(IP)["status"] == STATUS_EXPIRED


# =====================================================================
# regression 6A–6C
# =====================================================================
def test_duplicate_guard_still_applies_with_repository(tmp_path):
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path)
    feed_block(pipe)
    for i in range(5):
        trace = pipe.process(eve(offset=20 + i * 0.5))

    assert trace["duplicate_block"] is True
    assert enforcer.added == [IP]
    assert len([a for a in rows(db, "actions") if a["action"] == ACTION_BLOCK]) == 1


def test_remove_failed_guard_still_applies_with_repository(tmp_path):
    pipe, repo, store, enforcer, clock, mgr, db = build_stack(tmp_path, remove_ok=False)
    feed_block(pipe)
    clock.advance(301)
    mgr.expire_due()
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED

    for i in range(5):
        trace = pipe.process(eve(offset=400 + i * 0.5))

    assert trace["block_suppressed"] is True
    assert trace["duplicate_block"] is False
    assert store.get_block(IP)["status"] == STATUS_REMOVE_FAILED


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
