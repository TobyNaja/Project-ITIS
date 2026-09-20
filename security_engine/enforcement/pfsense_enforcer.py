"""
security_engine/enforcement/pfsense_enforcer.py — Phase 8 Enforcement

Mechanism layer ล้วน: รับคำสั่ง block/unblock แล้วทำผ่าน SSH → pfctl → table
*** ไม่มี logic Risk / Rule / 300s expiry ปนอยู่ ***
  - การตัดสินใจว่าจะ block ไหม เกิดที่ Phase 6 (Rule Engine)
  - lifecycle BLOCK → 300s → UNBLOCK เป็นของ Phase 9
  - Enforcer รู้แค่ "block this IP" / "unblock this IP" / "is it blocked"

หลักการที่ล็อก:
  Command success ≠ Enforcement success
  ทุก add/remove ต้อง read-back table แล้วยืนยันว่า IP อยู่/หายจริง
  ก่อนจะรายงานว่าสำเร็จ

pfSense control:
  block   : pfctl -t <table> -T add <ip>
  unblock : pfctl -t <table> -T delete <ip>
  verify  : pfctl -t <table> -T show
"""
import ipaddress
import subprocess
from dataclasses import dataclass


class EnforcementError(Exception):
    """IP invalid, SSH ล้มเหลว, หรือ pfctl error"""


@dataclass
class EnforcementResult:
    action: str            # "add" | "remove"
    ip: str
    command_ok: bool       # return code ของ pfctl = 0 ไหม
    verified: bool         # read-back ยืนยันสถานะที่ต้องการไหม
    status: str            # "ENFORCED" | "REMOVED" | "FAILED"

    @property
    def success(self) -> bool:
        # สำเร็จก็ต่อเมื่อ command ผ่าน "และ" verify ผ่าน
        return self.command_ok and self.verified

    def __str__(self):
        return (f"[ENFORCE] {self.action} {self.ip} "
                f"cmd_ok={self.command_ok} verified={self.verified} "
                f"-> {self.status}")


def validate_ip(ip: str) -> str:
    """คืน canonical IP string ถ้า valid; ไม่งั้น raise EnforcementError
    กัน command injection — ห้ามเอา input ดิบไปต่อ command"""
    try:
        return str(ipaddress.ip_address(ip))
    except (ValueError, TypeError):
        raise EnforcementError(f"invalid IP: {ip!r}")


class PFSenseEnforcer:
    def __init__(self, host, table="ITIS_BLOCK_TEST",
                 ssh_opts=None, timeout=10):
        # host เช่น "admin@192.168.227.150"; ใช้ SSH key (non-interactive)
        self.host = host
        self.table = table
        self.timeout = timeout
        self.ssh_opts = ssh_opts or [
            "-T",
            "-o", "BatchMode=yes",          # ต้องมี key; ไม่ค้างรอ password
            "-o", "ConnectTimeout=5",
        ]

    # ---- SSH layer ----
    def _run(self, remote_cmd):
        """รัน remote command ผ่าน SSH; คืน (returncode, stdout)
        remote_cmd เป็น list ของ token (ประกอบเองในเมธอด ไม่รับจากผู้ใช้)"""
        argv = ["ssh", *self.ssh_opts, self.host, *remote_cmd]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            raise EnforcementError(f"SSH timeout to {self.host}")
        except FileNotFoundError:
            raise EnforcementError("ssh binary not found")
        return proc.returncode, proc.stdout

    # ---- read-back ----
    def get_blocked_ips(self):
        """อ่าน table ปัจจุบัน คืน set ของ IP (canonical)"""
        rc, out = self._run(["pfctl", "-t", self.table, "-T", "show"])
        if rc != 0:
            raise EnforcementError(
                f"pfctl show failed (rc={rc}) on table {self.table}")
        ips = set()
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ips.add(str(ipaddress.ip_address(line)))
            except ValueError:
                continue     # ข้ามบรรทัดที่ไม่ใช่ IP (header/noise)
        return ips

    def is_blocked(self, ip) -> bool:
        """read-back อย่างเดียว — IP อยู่ใน table ไหม"""
        ip = validate_ip(ip)
        return ip in self.get_blocked_ips()

    # ---- enforcement ----
    def add_block(self, ip) -> EnforcementResult:
        ip = validate_ip(ip)                       # 1) validate ก่อนแตะ pfSense
        rc, _ = self._run(["pfctl", "-t", self.table, "-T", "add", ip])
        command_ok = (rc == 0)
        verified = self.is_blocked(ip)             # 2) read-back เสมอ
        status = "ENFORCED" if (command_ok and verified) else "FAILED"
        return EnforcementResult("add", ip, command_ok, verified, status)

    def remove_block(self, ip) -> EnforcementResult:
        ip = validate_ip(ip)
        rc, _ = self._run(["pfctl", "-t", self.table, "-T", "delete", ip])
        command_ok = (rc == 0)
        verified = not self.is_blocked(ip)         # verify = หายจริง
        status = "REMOVED" if (command_ok and verified) else "FAILED"
        return EnforcementResult("remove", ip, command_ok, verified, status)