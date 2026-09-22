"""
tests/test_logging_and_errors.py — STEP 8: NFR-02 / NFR-03

NFR-03 Logging:
    config.yaml (system.log_path / system.log_level) -> configure_logging()
    INFO ขึ้นไปลงไฟล์ · DEBUG เปิดได้จาก config · timestamp เป็น UTC (NFR-04)

NFR-02 Error handling:
    external call (SSH / subprocess / SQLite) -> try/except + timeout + log
    event เดียวพัง -> log แล้วไปต่อ ไม่ล้มทั้ง engine
"""
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

import run_phase4
from security_engine import logging_config
from security_engine.enforcement.pfsense_enforcer import (
    PFSenseEnforcer, EnforcementError,
)
from security_engine.ingestion import eve_reader
from security_engine.logging_config import (
    configure_logging, configure_from_settings, VALID_LOG_LEVELS,
)
from security_engine.settings import load_settings
from security_engine.storage import schema

PRODUCTION_MODULES = sorted(
    p for p in Path("security_engine").rglob("*.py")
    if "__pycache__" not in str(p)
)


@pytest.fixture(autouse=True)
def restore_logging():
    """กัน handler ของเทสหลุดไปกวนเทสอื่น"""
    root = logging.getLogger()
    before = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        if handler not in before[0]:
            root.removeHandler(handler)
            handler.close()
    root.handlers = before[0]
    root.setLevel(before[1])


# ---------------------------------------------------------------- 1. log file
def test_configure_logging_creates_file(tmp_path):
    log_path = tmp_path / "logs" / "engine.log"
    configure_logging(log_path, console=False)
    logging.getLogger("itis.test").info("hello engine")
    assert log_path.is_file()
    assert "hello engine" in log_path.read_text(encoding="utf-8")


def test_creates_parent_directory(tmp_path):
    log_path = tmp_path / "deep" / "nested" / "engine.log"
    configure_logging(log_path, console=False)
    logging.getLogger("itis.test").warning("x")
    assert log_path.is_file()


def test_info_level_excludes_debug(tmp_path):
    log_path = tmp_path / "engine.log"
    configure_logging(log_path, level="INFO", console=False)
    logger = logging.getLogger("itis.test")
    logger.debug("debug-line")
    logger.info("info-line")

    content = log_path.read_text(encoding="utf-8")
    assert "info-line" in content
    assert "debug-line" not in content


def test_debug_level_from_config(tmp_path):
    log_path = tmp_path / "engine.log"
    configure_logging(log_path, level="DEBUG", console=False)
    logging.getLogger("itis.test").debug("debug-line")
    assert "debug-line" in log_path.read_text(encoding="utf-8")


def test_warning_and_error_are_recorded(tmp_path):
    log_path = tmp_path / "engine.log"
    configure_logging(log_path, console=False)
    logging.getLogger("itis.test").warning("warn-line")
    logging.getLogger("itis.test").error("error-line")

    content = log_path.read_text(encoding="utf-8")
    assert "WARNING" in content and "warn-line" in content
    assert "ERROR" in content and "error-line" in content


def test_log_timestamp_is_utc(tmp_path):
    """NFR-04: log ต้องเป็น UTC ไม่ใช่เวลาเครื่อง"""
    log_path = tmp_path / "engine.log"
    configure_logging(log_path, console=False)
    logging.getLogger("itis.test").info("utc-check")

    line = log_path.read_text(encoding="utf-8").strip().splitlines()[0]
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b", line), line

    # เวลาใน log ต้องตรงกับ UTC จริง ไม่ใช่เวลาเครื่อง
    stamp = datetime.strptime(line.split()[0], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - stamp).total_seconds()) < 60


def test_logger_name_and_level_in_output(tmp_path):
    log_path = tmp_path / "engine.log"
    configure_logging(log_path, console=False)
    logging.getLogger("security_engine.demo").info("named")
    content = log_path.read_text(encoding="utf-8")
    assert "security_engine.demo" in content
    assert "INFO" in content


def test_configure_is_idempotent(tmp_path):
    """เรียกซ้ำต้องไม่ทำให้ log ซ้ำบรรทัด"""
    log_path = tmp_path / "engine.log"
    configure_logging(log_path, console=False)
    configure_logging(log_path, console=False)
    logging.getLogger("itis.test").info("only-once")

    lines = [l for l in log_path.read_text(encoding="utf-8").splitlines()
             if "only-once" in l]
    assert len(lines) == 1


@pytest.mark.parametrize("level", VALID_LOG_LEVELS)
def test_all_valid_levels_accepted(tmp_path, level):
    configure_logging(tmp_path / "engine.log", level=level, console=False)


def test_invalid_level_rejected(tmp_path):
    with pytest.raises(ValueError):
        configure_logging(tmp_path / "engine.log", level="VERBOSE", console=False)


def test_configure_from_settings(tmp_path, monkeypatch):
    settings = load_settings()                       # config จริงของ repo
    monkeypatch.chdir(tmp_path)                      # อย่าเขียน logs/ ลง repo
    configure_from_settings(settings, console=False)

    logging.getLogger("itis.test").info("from-settings")
    written = Path(settings.system.log_path)
    assert written.is_file()
    assert "from-settings" in written.read_text(encoding="utf-8")


# ---------------------------------------------------------------- 2. no print()
def test_no_print_in_production_modules():
    """NFR-03: engine ใช้ logging ไม่ใช่ print"""
    offenders = []
    for path in PRODUCTION_MODULES + [Path("run_phase4.py")]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"(?<!\w)print\s*\(", line):
                offenders.append(f"{path}:{number}")
    assert offenders == []


def test_production_modules_use_module_logger():
    """โมดูลที่ log ต้องใช้ getLogger(__name__) ไม่ตั้งค่า root เอง"""
    for path in PRODUCTION_MODULES:
        text = path.read_text(encoding="utf-8")
        if "log." in text and path.name != "logging_config.py":
            assert "logging.getLogger(__name__)" in text, path


# ---------------------------------------------------------------- 3. external calls
def test_ssh_timeout_is_logged_and_raised(caplog):
    enforcer = PFSenseEnforcer("admin@198.51.100.10", timeout=1)

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=1)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(EnforcementError):
            enforcer._run(["pfctl", "-t", "x", "-T", "show"], ) if False else None
            import security_engine.enforcement.pfsense_enforcer as mod
            original = mod.subprocess.run
            mod.subprocess.run = boom
            try:
                enforcer._run(["pfctl"])
            finally:
                mod.subprocess.run = original
    assert any("timeout" in r.message.lower() for r in caplog.records)


def test_missing_ssh_binary_is_logged(monkeypatch, caplog):
    enforcer = PFSenseEnforcer("admin@198.51.100.10")
    monkeypatch.setattr(
        "security_engine.enforcement.pfsense_enforcer.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))

    with caplog.at_level(logging.ERROR):
        with pytest.raises(EnforcementError):
            enforcer._run(["pfctl"])
    assert any("ssh" in r.message.lower() for r in caplog.records)


def test_enforcer_has_timeout_by_default():
    assert PFSenseEnforcer("h").timeout > 0


def test_sqlite_connect_has_timeout(tmp_path, monkeypatch):
    """NFR-02: external call ต้องมี timeout — กัน WAL contention ค้างไม่จบ"""
    captured = {}
    import sqlite3
    real_connect = sqlite3.connect

    def spy(path, *args, **kwargs):
        captured.update(kwargs)
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(schema.sqlite3, "connect", spy)
    schema.connect(tmp_path / "x.db").close()
    assert captured.get("timeout", 0) > 0


def test_eve_reader_missing_ssh_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(eve_reader.subprocess, "Popen",
                        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    with caplog.at_level(logging.ERROR):
        with pytest.raises(FileNotFoundError):
            list(eve_reader.stream_events("h", "/tmp/eve.json"))
    assert any("ssh" in r.message.lower() for r in caplog.records)


def test_eve_reader_kills_stuck_ssh(monkeypatch, caplog):
    """terminate แล้วไม่จบใน 5s -> kill ไม่ปล่อยให้ค้าง"""
    events = {"killed": False}

    class StuckProc:
        def __init__(self):
            self.stdout = type("S", (), {"readline": lambda s: ""})()

        def terminate(self):
            pass

        def wait(self, timeout=None):
            if not events["killed"]:
                raise subprocess.TimeoutExpired(cmd="ssh", timeout=timeout)
            return 0

        def kill(self):
            events["killed"] = True

    monkeypatch.setattr(eve_reader.subprocess, "Popen", lambda *a, **k: StuckProc())
    with caplog.at_level(logging.WARNING):
        list(eve_reader.stream_events("h", "/tmp/eve.json"))
    assert events["killed"] is True


# ---------------------------------------------------------------- 4. engine continues
class _ExplodingPipeline:
    def __init__(self, fail_on):
        self.fail_on = fail_on
        self.seen = []

    def process(self, event):
        self.seen.append(event["src_ip"])
        if event["src_ip"] == self.fail_on:
            raise RuntimeError("database is locked")
        return {"src_ip": event["src_ip"], "correlation_matched": False,
                "decision": None}


class _NoopRunner:
    def __init__(self):
        self.lifecycle = type("L", (), {"reconcile": lambda s, now=None: []})()
        self.stopped = False

    def start(self):
        pass

    def stop(self, *a, **k):
        self.stopped = True


def test_one_failing_event_does_not_stop_engine(caplog):
    """NFR-02: engine ห้าม crash เพราะ event เดียว"""
    pipeline = _ExplodingPipeline(fail_on="198.51.100.2")
    runner = _NoopRunner()
    events = [{"src_ip": f"198.51.100.{i}"} for i in (1, 2, 3)]

    with caplog.at_level(logging.ERROR):
        run_phase4.run(pipeline, runner, events)

    assert pipeline.seen == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    assert runner.stopped is True
    assert any("198.51.100.2" in r.message or "198.51.100.2" in str(r.args)
               for r in caplog.records)


def test_runner_error_callback_logs(tmp_path, caplog):
    """on_error ของ LifecycleRunner ต้อง log ไม่ใช่ print/เงียบ"""
    pipeline, runner, _ = run_phase4.build_pipeline(
        db_path=str(tmp_path / "x.db"),
        enforcer=type("E", (), {"add_block": lambda s, ip: None,
                                "remove_block": lambda s, ip: None,
                                "is_blocked": lambda s, ip: False})(),
        correlator=object())

    with caplog.at_level(logging.ERROR):
        runner.on_error(RuntimeError("boom"))
    assert any("boom" in str(r.message) + str(r.args) for r in caplog.records)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
