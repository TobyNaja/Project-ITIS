"""
tests/test_wiring.py — Phase 11.3 End-to-End Wiring (fake components)

พิสูจน์ว่า architecture ต่อกันจริง — ยังไม่ใช่ Real E2E (ไม่ต่อ Suricata/pfSense)
ใช้ fake stream_events + fake enforcer -> ไม่แตะ pfSense จริง
"""
import threading

import pytest

import run_phase4
from security_engine.pipeline import SecurityPipeline
from security_engine.lifecycle.runner import LifecycleRunner
from security_engine.policy.rule_engine import BLOCK


# ---- fakes ----
class FakeResult:
    def __init__(self, ok=True):
        self.command_ok = ok
        self.verified = ok
        self.success = ok
        self.status = "ENFORCED" if ok else "FAILED"


class FakeEnforcer:
    """แทน PFSenseEnforcer — ไม่ยิง SSH/pfSense"""
    def __init__(self):
        self.added = []
        self.removed = []

    def add_block(self, ip):
        self.added.append(ip)
        return FakeResult(True)

    def remove_block(self, ip):
        self.removed.append(ip)
        return FakeResult(True)

    def is_blocked(self, ip):
        return ip in self.added and ip not in self.removed

    def get_blocked_ips(self):
        return set(self.added) - set(self.removed)


class FakeCorrelator:
    def __init__(self, match=None):
        self.match = match

    def process(self, event):
        return self.match


@pytest.fixture
def allowlist_file(tmp_path):
    f = tmp_path / "allowlist.yaml"
    f.write_text('allowlist:\n  - "10.9.9.9"\n', encoding="utf-8")
    return f


def _build(tmp_path, allowlist_file, match=None):
    enf = FakeEnforcer()
    corr = FakeCorrelator(match)
    pipeline, runner, lock = run_phase4.build_pipeline(
        allowlist_path=str(allowlist_file),
        db_path=str(tmp_path / "wiring.db"),
        expire_interval=0.05,
        enforcer=enf,
        correlator=corr,
    )
    return pipeline, runner, lock, enf


# ---- 1. component ถูกสร้างและส่งเข้า Pipeline ถูกตัว ----
def test_build_wires_components(tmp_path, allowlist_file):
    pipeline, runner, lock, enf = _build(tmp_path, allowlist_file)
    assert isinstance(pipeline, SecurityPipeline)
    assert isinstance(runner, LifecycleRunner)
    # lifecycle ของ pipeline กับ runner เป็นตัวเดียวกัน
    assert pipeline.lifecycle is runner.lifecycle


# ---- 2. shared lock เป็นตัวเดียวกัน ----
def test_shared_lock_is_same(tmp_path, allowlist_file):
    pipeline, runner, lock, enf = _build(tmp_path, allowlist_file)
    assert pipeline.lock is runner.lock is lock


# ---- 3 + 4. runner start + event ถึง pipeline.process ----
def test_events_flow_through_pipeline(tmp_path, allowlist_file):
    # match ที่ให้ BLOCK: sev1 เป้าเดียว 5 events window แคบ -> CRITICAL
    match = {"src_ip": "1.2.3.4", "event_count": 5, "window_seconds": 1.0,
             "events": [{"dest_ip": "x", "severity": 1} for _ in range(5)]}
    pipeline, runner, lock, enf = _build(tmp_path, allowlist_file, match=match)

    events = [{"src_ip": "1.2.3.4", "timestamp": "2026-09-20T10:00:00+00:00",
               "received_at": "2026-09-20T10:00:00+00:00"}]

    run_phase4.run(pipeline, runner, events)   # start -> วน -> finally stop

    assert enf.added == ["1.2.3.4"]            # event ถึง process แล้ว BLOCK จริง
    assert not runner.is_running()             # finally stop เรียกแล้ว


# ---- 5. finally เรียก runner.stop() แม้เกิด exception ----
def test_runner_stopped_on_exception(tmp_path, allowlist_file):
    pipeline, runner, lock, enf = _build(tmp_path, allowlist_file)

    def boom_source():
        yield {"src_ip": "1.1.1.1", "timestamp": "t", "received_at": "t"}
        raise RuntimeError("stream died")

    with pytest.raises(RuntimeError):
        run_phase4.run(pipeline, runner, boom_source())

    assert not runner.is_running()             # stop ถูกเรียกใน finally แม้ crash


# ---- 6. wiring test ไม่แตะ pfSense จริง (ใช้ FakeEnforcer) ----
def test_no_real_pfsense(tmp_path, allowlist_file):
    pipeline, runner, lock, enf = _build(tmp_path, allowlist_file)
    # enforcer ที่ต่ออยู่คือ FakeEnforcer ไม่ใช่ PFSenseEnforcer
    assert isinstance(enf, FakeEnforcer)
    assert pipeline.lifecycle.enforcer is enf


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))