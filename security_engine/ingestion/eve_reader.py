import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone

PFSENSE_HOST = os.environ.get("PFSENSE_HOST", "root@192.168.1.1")
EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/suricata_em0_xxx/eve.json")

SURICATA_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"   # e.g. 2026-09-19T16:20:01.123456+0700
SURICATA_TS_FMT_NO_MICROS = "%Y-%m-%dT%H:%M:%S%z"  # e.g. 2026-09-19T16:20:01+0700


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


def _parse_timestamp(ts_raw) -> datetime | None:
    """Parse Suricata timestamp robustly. Returns aware datetime or None."""
    if not ts_raw:
        return None
    if isinstance(ts_raw, datetime):
        ts = ts_raw
    elif isinstance(ts_raw, (int, float)):
        try:
            ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(ts_raw, str):
        ts = None
        s = ts_raw.strip()
        # 1) Suricata native: 2026-09-19T16:20:01.123456+0700
        for fmt in (SURICATA_TS_FMT, SURICATA_TS_FMT_NO_MICROS):
            try:
                ts = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        # 2) ISO-8601 with colon tz or Z: 2026-09-19T16:20:01.123+07:00
        if ts is None:
            try:
                ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None
    else:
        return None

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def normalize(ev: dict) -> dict | None:
    """Return normalized alert or None if the record must be skipped."""
    if not isinstance(ev, dict):
        return None
    alert = ev.get("alert", {})
    if not isinstance(alert, dict):
        alert = {}
    ts = _parse_timestamp(ev.get("timestamp"))
    if ts is None:
        return None  # caller skips; one bad line must not kill the stream
    return {
        # เวลาที่ Suricata เห็น packet -> ใช้ตัวนี้ใน Correlation window เสมอ
        "timestamp": ts,
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


def stream_events(host: str | None = None, eve_path: str | None = None):
    """Generator: yield normalized alert ทีละ event แบบ real-time.

    Priority: explicit arg > env var > module default.
    Resolved lazily so .env loaded in main() still applies.
    """
    host = host or os.environ.get("PFSENSE_HOST", PFSENSE_HOST)
    eve_path = eve_path or os.environ.get("EVE_PATH", EVE_PATH)
    if "CHANGE_ME" in eve_path:
        raise ValueError(
            f"EVE_PATH still contains placeholder: {eve_path!r}. "
            "Copy .env.example to .env and set EVE_PATH, e.g. "
            "/var/log/suricata/suricata_em224404/eve.json"
        )
    try:
        proc = subprocess.Popen(
            _ssh_cmd(host, eve_path),
            stdin=subprocess.DEVNULL,          # ssh ไม่แตะ TTY ของเรา
            stdout=subprocess.PIPE,
            stderr=None,                       # ให้ error ของ ssh โผล่บนจอตรงๆ (ไม่ต้อง PIPE แล้วลืมอ่าน)
            text=True,
            bufsize=1,                         # line-buffered
        )
    except FileNotFoundError:
        raise RuntimeError("`ssh` binary not found on PATH")
    except OSError as exc:
        raise RuntimeError(f"failed to start ssh to {host}: {exc}")
    if proc.stdout is None:
        proc.terminate()
        raise RuntimeError("ssh stdout pipe failed")
    try:
        for line in iter(proc.stdout.readline, ""):
            line = line.strip()            # ตัดทั้ง \r และ \n เผื่อมีหลุดมา
            if not line:
                # ssh exited? stop silently only after reporting exit code.
                if proc.poll() is not None:
                    break
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue                   # บรรทัดขาด (ตอน log rotate ฯลฯ)
            if ev.get("event_type") != "alert":
                continue
            try:
                norm = normalize(ev)
            except Exception:
                continue  # one bad record must never kill the stream
            if norm is None:
                continue
            yield norm
        rc = proc.poll()
        if rc is None:
            pass  # generator closed early by caller; cleanup below
        elif rc != 0:
            print(
                f"[eve_reader] ssh exited with code {rc} "
                f"(host={host} eve={eve_path})",
                file=sys.stderr,
                flush=True,
            )
        else:
            print("[eve_reader] ssh stream ended (EOF)", file=sys.stderr, flush=True)
    finally:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except Exception:
            pass
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass

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
