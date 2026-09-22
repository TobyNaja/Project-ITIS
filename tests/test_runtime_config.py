"""
tests/test_runtime_config.py — Phase 11.3 Runtime Configuration

พิสูจน์ว่า entry point รันได้จริงด้วย configuration ที่ reproducible:
    ITIS_PFSENSE_HOST / ITIS_EVE_PATH -> main() -> stream_events(host, eve_path)
    config/allowlist.yaml (default policy file) -> load_allowlist() -> RuleEngine

ไม่แตะ pfSense จริง: monkeypatch stream_events/run และ inject FakeEnforcer
"""
from pathlib import Path

import pytest

import run_phase4
from security_engine.policy.allowlist import load_allowlist

ROOT = Path(run_phase4.__file__).resolve().parent

HOST = "admin@198.51.100.10"
EVE = "/var/log/suricata/suricata_test0/eve.json"


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


@pytest.fixture
def clean_env(monkeypatch):
    """เริ่มทุก test จากสถานะที่ไม่มี env ทั้งสองตัว

    และกัน main() ไม่ให้ตั้ง logging จริง (จะไปเขียน logs/engine.log ของ repo
    และแย่งคุม root logger กับเทสอื่น)
    """
    monkeypatch.delenv(run_phase4.ENV_PFSENSE_HOST, raising=False)
    monkeypatch.delenv(run_phase4.ENV_EVE_PATH, raising=False)
    monkeypatch.setattr(run_phase4, "configure_from_settings", lambda *a, **k: None)
    return monkeypatch


# ---- 1. require_env อ่านค่าจาก environment จริง ----
def test_require_env_reads_pfsense_host(clean_env):
    clean_env.setenv(run_phase4.ENV_PFSENSE_HOST, HOST)
    assert run_phase4.require_env(run_phase4.ENV_PFSENSE_HOST) == HOST


def test_require_env_reads_eve_path(clean_env):
    clean_env.setenv(run_phase4.ENV_EVE_PATH, EVE)
    assert run_phase4.require_env(run_phase4.ENV_EVE_PATH) == EVE


# ---- 2. env หาย/ว่าง -> fail fast พร้อมบอกชื่อตัวแปร ----
def test_missing_env_raises_with_var_name(clean_env):
    with pytest.raises(run_phase4.ConfigError) as exc:
        run_phase4.require_env(run_phase4.ENV_PFSENSE_HOST)
    assert run_phase4.ENV_PFSENSE_HOST in str(exc.value)


def test_blank_env_raises(clean_env):
    clean_env.setenv(run_phase4.ENV_EVE_PATH, "   ")
    with pytest.raises(run_phase4.ConfigError):
        run_phase4.require_env(run_phase4.ENV_EVE_PATH)


# ---- 3. main() ส่ง host + eve_path เข้า stream_events ครบทั้งคู่ ----
def test_main_passes_host_and_eve_path(clean_env):
    clean_env.setenv(run_phase4.ENV_PFSENSE_HOST, HOST)
    clean_env.setenv(run_phase4.ENV_EVE_PATH, EVE)
    seen = {}

    def fake_build(**kwargs):
        seen["build"] = kwargs
        return "pipeline", "runner", "lock"

    def fake_stream(host, eve_path, on_stats=None):
        seen["stream"] = (host, eve_path)
        seen["on_stats"] = on_stats
        return iter(())

    class FakeMonitor:
        def on_stats(self, event):
            seen.setdefault("stats_events", []).append(event)

    fake_monitor = FakeMonitor()

    def fake_health(settings, *, host, repository=None, controller=None):
        seen["health"] = (host, repository)
        return fake_monitor, "health_runner"

    def fake_run(p, r, src, health_runner=None):
        seen["run"] = (p, r)
        seen["health_runner"] = health_runner

    clean_env.setattr(run_phase4, "build_pipeline", fake_build)
    # ห้ามแตะ data/experiment.db ของจริง (หลักฐาน pre-freeze) ระหว่างรัน test
    clean_env.setattr(run_phase4, "AuditRepository", lambda db_path: f"repo:{db_path}")
    clean_env.setattr(run_phase4, "build_health", fake_health)
    clean_env.setattr(run_phase4, "stream_events", fake_stream)
    clean_env.setattr(run_phase4, "run", fake_run)

    run_phase4.main()

    assert seen["stream"] == (HOST, EVE)      # eve_path ไม่ถูกลืม (bug เดิม)
    assert seen["build"]["host"] == HOST
    assert seen["run"] == ("pipeline", "runner")
    # FR-12: stats callback ต้องถูกต่อเข้า EVE stream จริง ไม่ใช่สร้าง monitor ทิ้งไว้เฉย ๆ
    assert seen["on_stats"] == fake_monitor.on_stats
    assert seen["health_runner"] == "health_runner"
    # audit chain + recovery_events ใช้ repository ตัวเดียวกัน (ไฟล์ DB เดียว)
    assert seen["health"][1] == seen["build"]["repository"]


# ---- 4. env หาย -> main() พังก่อนประกอบระบบ (ไม่แตะ pfSense/db) ----
def test_main_fails_fast_before_building(clean_env):
    def must_not_run(**kwargs):
        raise AssertionError("build_pipeline ไม่ควรถูกเรียกเมื่อ env ไม่ครบ")

    clean_env.setattr(run_phase4, "build_pipeline", must_not_run)

    with pytest.raises(run_phase4.ConfigError):
        run_phase4.main()


def test_main_fails_fast_when_only_host_set(clean_env):
    clean_env.setenv(run_phase4.ENV_PFSENSE_HOST, HOST)

    def must_not_run(**kwargs):
        raise AssertionError("build_pipeline ไม่ควรถูกเรียกเมื่อ ITIS_EVE_PATH หาย")

    clean_env.setattr(run_phase4, "build_pipeline", must_not_run)

    with pytest.raises(run_phase4.ConfigError) as exc:
        run_phase4.main()
    assert run_phase4.ENV_EVE_PATH in str(exc.value)


# ---- 5. allowlist default: ไฟล์ต้องมีจริงและโหลดผ่าน (บั๊กเดิม: config/ ไม่มี) ----
def test_default_allowlist_file_exists_and_loads():
    f = ROOT / run_phase4.ALLOWLIST_PATH
    assert f.is_file(), f"ต้องมี {run_phase4.ALLOWLIST_PATH} ใน repo"
    assert load_allowlist(f) == set()          # default policy = ไม่ bypass ใครเลย


def test_build_pipeline_uses_default_allowlist(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)                    # ALLOWLIST_PATH เป็น path แบบ relative
    pipeline, runner, _ = run_phase4.build_pipeline(
        db_path=str(tmp_path / "rc.db"),
        enforcer=FakeEnforcer(),               # ไม่ต้องใช้ env host
        correlator=object(),
    )
    assert pipeline.rule_engine.allowlist == set()
    assert runner.lifecycle is pipeline.lifecycle


# ---- 6. host ของ enforcer จริงมาจาก env (และหาย env = พัง ไม่ใช่ต่อเครื่องมั่ว) ----
def test_build_pipeline_takes_host_from_env(tmp_path, clean_env):
    clean_env.chdir(ROOT)
    clean_env.setenv(run_phase4.ENV_PFSENSE_HOST, HOST)
    pipeline, runner, _ = run_phase4.build_pipeline(
        db_path=str(tmp_path / "rc.db"), correlator=object())
    assert pipeline.lifecycle.enforcer.host == HOST


def test_build_pipeline_without_host_or_env_raises(tmp_path, clean_env):
    clean_env.chdir(ROOT)
    with pytest.raises(run_phase4.ConfigError):
        run_phase4.build_pipeline(
            db_path=str(tmp_path / "rc.db"), correlator=object())


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
