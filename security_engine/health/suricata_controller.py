"""
security_engine/health/suricata_controller.py — Suricata process control (FR-12/FR-13)

หน้าที่เดียว: ถาม/สั่ง process ของ Suricata บนเครื่องที่รัน IDS ผ่าน SSH
    is_running()  -> Suricata ยังเดินอยู่ไหม
    restart()     -> สั่ง restart ด้วย "คำสั่งที่ config ไว้เท่านั้น"

*** ไม่รู้จัก stats freshness *** — ความสดของ stats เป็นหน้าที่ของ HealthMonitor
ซึ่งได้ข้อมูลจาก EVE reader (on_stats) อยู่แล้ว ไม่ต้องยิง SSH ซ้ำ

*** restart_command ต้องมาจาก config เท่านั้น *** — pfSense เป็น FreeBSD ไม่มี systemd
การเดาคำสั่ง (เช่น systemctl) แล้วใส่ลงโค้ดจะเป็นข้อมูลปลอมในระบบ
ถ้ายังไม่ได้ตั้งค่า -> restart() ล้มเหลวพร้อมเหตุผล ไม่ใช่ "สำเร็จแบบเงียบ"
"""
import logging
import shlex
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)

DEFAULT_PROCESS_NAME = "suricata"
DEFAULT_TIMEOUT = 10

# หมายเหตุ: pgrep มีอยู่ใน FreeBSD base (pfSense) — ต้องยืนยันกับเครื่องจริงตอน dry run
PROCESS_CHECK_TEMPLATE = "pgrep -x {name}"


@dataclass(frozen=True)
class RestartResult:
    ok: bool
    command: str = ""
    returncode: int = None
    error: str = None

    def __str__(self):
        state = "ok" if self.ok else f"failed ({self.error})"
        return f"[RESTART] {self.command!r} -> {state}"


class SuricataController:
    """คุม Suricata ผ่าน SSH — ไม่มี logic ของ health/recovery อยู่ในนี้"""

    def __init__(self, host, restart_command="", process_name=DEFAULT_PROCESS_NAME,
                 ssh_opts=None, timeout=DEFAULT_TIMEOUT):
        self.host = host
        self.restart_command = (restart_command or "").strip()
        self.process_name = process_name
        self.timeout = timeout
        self.ssh_opts = ssh_opts or [
            "-T",
            "-o", "BatchMode=yes",          # ต้องมี key; ไม่ค้างรอ password
            "-o", "ConnectTimeout=5",
        ]

    # ---- SSH layer (NFR-02: try/except + timeout + log) ----
    def _run(self, remote_command):
        argv = ["ssh", *self.ssh_opts, self.host, remote_command]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout)
        except subprocess.TimeoutExpired:
            log.error("SSH timeout %ss ตอนสั่ง %r ที่ %s",
                      self.timeout, remote_command, self.host)
            return None
        except FileNotFoundError:
            log.error("ไม่พบคำสั่ง ssh บนเครื่องนี้ — ตรวจ/กู้ Suricata ไม่ได้")
            return None
        except OSError as exc:
            log.error("เรียก ssh ไปยัง %s ไม่สำเร็จ: %s", self.host, exc)
            return None
        return proc

    # ---- public ----
    def is_running(self) -> bool:
        """pgrep บนเครื่อง IDS — rc=0 แปลว่ามี process อยู่

        ติดต่อไม่ได้/timeout -> ถือว่า "ไม่รู้ว่าเดินอยู่" = False
        (conservative: ปล่อยให้ health ลงไป DEGRADED ดีกว่าบอกว่าปกติทั้งที่ตรวจไม่ได้)
        """
        proc = self._run(PROCESS_CHECK_TEMPLATE.format(name=shlex.quote(self.process_name)))
        if proc is None:
            return False
        return proc.returncode == 0

    def restart(self) -> RestartResult:
        """สั่ง restart ด้วยคำสั่งจาก config — ไม่มี default ที่เดาเอง"""
        if not self.restart_command:
            message = ("ยังไม่ได้ตั้ง health.restart_command ใน config — "
                       "ไม่สามารถ restart Suricata ได้")
            log.error(message)
            return RestartResult(ok=False, command="", error=message)

        proc = self._run(self.restart_command)
        if proc is None:
            return RestartResult(ok=False, command=self.restart_command,
                                 error="ssh ล้มเหลว/timeout")

        if proc.returncode != 0:
            error = (proc.stderr or "").strip() or f"rc={proc.returncode}"
            log.error("restart Suricata ไม่สำเร็จที่ %s: %s", self.host, error)
            return RestartResult(ok=False, command=self.restart_command,
                                 returncode=proc.returncode, error=error)

        log.info("สั่ง restart Suricata ที่ %s แล้ว (%s)", self.host, self.restart_command)
        return RestartResult(ok=True, command=self.restart_command, returncode=0)
