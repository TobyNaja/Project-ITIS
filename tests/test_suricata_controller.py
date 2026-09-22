"""
tests/test_suricata_controller.py — STEP 9A: Suricata process control (FR-12/FR-13)

ขอบเขตของ controller คือ "ถาม/สั่ง process" เท่านั้น:
    is_running() -> pgrep บนเครื่อง IDS
    restart()    -> ใช้ health.restart_command จาก config เท่านั้น

สิ่งที่ test ชุดนี้ต้องกันไว้:
- ห้ามมี default restart command ในโค้ด (pfSense = FreeBSD ไม่มี systemd)
- ติดต่อ SSH ไม่ได้ ต้องไม่โยน exception ออกนอก controller (NFR-02)
- ตรวจไม่ได้ = ถือว่าไม่ปกติ (conservative) ไม่ใช่รายงานว่า healthy
"""
import subprocess
from pathlib import Path

import pytest

from security_engine.health import suricata_controller as sc
from security_engine.health.suricata_controller import RestartResult, SuricataController

HOST = "admin@198.51.100.10"
RESTART_CMD = "/usr/local/etc/rc.d/suricata restart"


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Recorder:
    """แทน subprocess.run — เก็บ argv ทุกครั้งที่ถูกเรียก"""

    def __init__(self, result=None, raises=None):
        self.result = result if result is not None else FakeProc(0)
        self.raises = raises
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.raises is not None:
            raise self.raises
        return self.result

    @property
    def last_argv(self):
        return self.calls[-1][0]

    @property
    def remote_command(self):
        return self.last_argv[-1]


@pytest.fixture
def controller():
    return SuricataController(HOST, restart_command=RESTART_CMD)


def patch_run(monkeypatch, recorder):
    monkeypatch.setattr(sc.subprocess, "run", recorder)
    return recorder


# ---- 1. is_running: อ่านผลจาก return code ----
def test_is_running_true_when_pgrep_succeeds(monkeypatch, controller):
    rec = patch_run(monkeypatch, Recorder(FakeProc(0, stdout="4321\n")))
    assert controller.is_running() is True
    assert "pgrep" in rec.remote_command
    assert "suricata" in rec.remote_command
    assert rec.last_argv[0] == "ssh"
    assert HOST in rec.last_argv


def test_is_running_false_when_pgrep_finds_nothing(monkeypatch, controller):
    patch_run(monkeypatch, Recorder(FakeProc(1)))
    assert controller.is_running() is False


def test_process_name_is_configurable(monkeypatch):
    rec = patch_run(monkeypatch, Recorder(FakeProc(0)))
    SuricataController(HOST, process_name="suricata-ids").is_running()
    assert "suricata-ids" in rec.remote_command


# ---- 2. SSH ล้มเหลว -> False + ไม่ระเบิดออกนอก (NFR-02) ----
@pytest.mark.parametrize("error", [
    subprocess.TimeoutExpired(cmd="ssh", timeout=10),
    FileNotFoundError("ssh"),
    OSError("network unreachable"),
])
def test_is_running_false_when_ssh_unusable(monkeypatch, controller, error, caplog):
    patch_run(monkeypatch, Recorder(raises=error))
    with caplog.at_level("ERROR"):
        assert controller.is_running() is False
    assert caplog.records, "ต้อง log ERROR เมื่อติดต่อเครื่อง IDS ไม่ได้"


def test_ssh_timeout_is_bounded(monkeypatch, controller):
    rec = patch_run(monkeypatch, Recorder(FakeProc(0)))
    controller.is_running()
    assert rec.calls[-1][1]["timeout"] == controller.timeout


# ---- 3. restart ต้องมาจาก config เท่านั้น ----
def test_restart_uses_configured_command_verbatim(monkeypatch, controller):
    rec = patch_run(monkeypatch, Recorder(FakeProc(0)))
    result = controller.restart()
    assert result.ok is True
    assert result.returncode == 0
    assert result.command == RESTART_CMD
    assert rec.remote_command == RESTART_CMD


def test_restart_fails_when_command_not_configured(monkeypatch, caplog):
    rec = patch_run(monkeypatch, Recorder(FakeProc(0)))
    ctrl = SuricataController(HOST, restart_command="")
    with caplog.at_level("ERROR"):
        result = ctrl.restart()
    assert result.ok is False
    assert "restart_command" in result.error
    assert rec.calls == [], "ยังไม่ได้ตั้งค่า -> ห้ามยิงคำสั่งอะไรไปที่เครื่องจริง"


def test_blank_restart_command_counts_as_unset(monkeypatch):
    patch_run(monkeypatch, Recorder(FakeProc(0)))
    assert SuricataController(HOST, restart_command="   ").restart().ok is False


def test_module_has_no_guessed_restart_command():
    """ห้าม hardcode คำสั่งของ OS ใด ๆ (systemctl/service) ใน "โค้ดที่รันจริง"

    docstring/คอมเมนต์พูดถึง systemctl ได้ (อธิบายว่าทำไมถึงห้าม) แต่ต้องไม่มี
    string constant ไหนที่กลายเป็นคำสั่งส่งไปเครื่องจริงได้
    """
    import ast

    tree = ast.parse(Path(sc.__file__).read_text(encoding="utf-8"))
    doc_nodes = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and body:
            first = body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                doc_nodes.add(id(first.value))

    code_literals = [node.value for node in ast.walk(tree)
                     if isinstance(node, ast.Constant)
                     and isinstance(node.value, str)
                     and id(node) not in doc_nodes]

    for banned in ("systemctl", "service suricata", "/etc/init.d", "rc.d"):
        offenders = [s for s in code_literals if banned in s]
        assert not offenders, f"เจอคำสั่งที่เดาเอง {banned!r}: {offenders}"


# ---- 4. restart ล้มเหลว -> รายงานสาเหตุ ไม่ใช่ 'สำเร็จเงียบ ๆ' ----
def test_restart_reports_nonzero_return_code(monkeypatch, controller):
    patch_run(monkeypatch, Recorder(FakeProc(1, stderr="suricata not found\n")))
    result = controller.restart()
    assert result.ok is False
    assert result.returncode == 1
    assert "suricata not found" in result.error


def test_restart_without_stderr_still_reports_code(monkeypatch, controller):
    patch_run(monkeypatch, Recorder(FakeProc(2, stderr="")))
    assert "rc=2" in controller.restart().error


def test_restart_handles_ssh_timeout(monkeypatch, controller):
    patch_run(monkeypatch, Recorder(
        raises=subprocess.TimeoutExpired(cmd="ssh", timeout=10)))
    result = controller.restart()
    assert result.ok is False
    assert result.command == RESTART_CMD


# ---- 5. RestartResult ----
def test_restart_result_str_shows_outcome():
    assert "ok" in str(RestartResult(ok=True, command="x"))
    assert "boom" in str(RestartResult(ok=False, command="x", error="boom"))


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
