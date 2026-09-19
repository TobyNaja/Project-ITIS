"""
security_engine/ingestion/eve_reader.py

pfSense (Suricata EVE JSON) --SSH--> normalized alert events

แก้ปัญหา 2 จุด:
  1. Buffering delay  -> stdbuf -oL ฝั่ง pfSense + อ่านทีละบรรทัดด้วย readline
  2. Staircase output -> ssh -T (ไม่ขอ PTY) + stdin=DEVNULL
     ssh ที่ได้ PTY (-t/-tt) และแชร์ TTY กับเรา จะสลับ terminal ฝั่ง SEC01 เป็น raw mode
     ทำให้ '\n' ไม่ถูกแปลงเป็น '\r\n' -> บรรทัดเยื้องขวาแบบขั้นบันได
"""
import json
import shlex
import subprocess
from datetime import datetime, timezone

# ---- แก้ให้ตรงกับเครื่องจริง ----
PFSENSE_HOST = "root@192.168.1.1"
EVE_PATH = "/var/log/suricata/suricata_CHANGE_ME/eve.json"

SURICATA_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"   # e.g. 2026-09-19T16:20:01.123456+0700


def _ssh_cmd(host: str, eve_path: str) -> list[str]:
    remote = f"stdbuf -oL tail -n 0 -F {shlex.quote(eve_path)}"
    return [
        "ssh",
        "-T",                               # ห้ามขอ PTY
        "-o", "BatchMode=yes",              # ไม่ค้างรอ password prompt
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        host,
        remote,
    ]


def normalize(ev: dict) -> dict:
    alert = ev.get("alert", {})
    return {
        # เวลาที่ Suricata เห็น packet -> ใช้ตัวนี้ใน Correlation window เสมอ
        "timestamp": datetime.strptime(ev["timestamp"], SURICATA_TS_FMT),
        # เวลาที่ SEC01 ได้รับ -> ใช้วัด ingest latency (ไม่ใช่ใช้ตัดสิน window)
        "received_at": datetime.now(timezone.utc),
        "src_ip": ev.get("src_ip"),
        "src_port": ev.get("src_port"),
        "dest_ip": ev.get("dest_ip"),
        "dest_port": ev.get("dest_port"),
        "proto": ev.get("proto"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "severity": alert.get("severity"),   # Suricata: 1 = สูงสุด
    }


def stream_events(host: str = PFSENSE_HOST, eve_path: str = EVE_PATH):
    """Generator: yield normalized alert ทีละ event แบบ real-time"""
    proc = subprocess.Popen(
        _ssh_cmd(host, eve_path),
        stdin=subprocess.DEVNULL,          # ssh ไม่แตะ TTY ของเรา
        stdout=subprocess.PIPE,
        stderr=None,                       # ให้ error ของ ssh โผล่บนจอตรงๆ (ไม่ต้อง PIPE แล้วลืมอ่าน)
        text=True,
        bufsize=1,                         # line-buffered
    )
    try:
        for line in iter(proc.stdout.readline, ""):
            line = line.strip()            # ตัดทั้ง \r และ \n เผื่อมีหลุดมา
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue                   # บรรทัดขาด (ตอน log rotate ฯลฯ)
            if ev.get("event_type") != "alert":
                continue
            yield normalize(ev)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    # ทดสอบ standalone: python3 -u -m security_engine.ingestion.eve_reader
    for e in stream_events():
        lag = (e["received_at"] - e["timestamp"]).total_seconds()
        print(
            f"[RAW EVENT] {e['timestamp'].isoformat()} "
            f"{e['src_ip']} -> {e['dest_ip']} "
            f"sid={e['signature_id']} sev={e['severity']} "
            f"ingest_lag={lag:.3f}s",
            flush=True,
        )
