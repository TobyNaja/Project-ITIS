"""
security_engine/ingestion/eve_reader.py — EVE JSON ingestion (Blueprint FR-01 / FR-02)

    Suricata EVE JSON ──(transport)──> raw line ──> parse ──> classify ──> normalized event

transport มีสองแบบ ใช้ parser ตัวเดียวกัน:
    LocalEveTail   อ่านไฟล์บนเครื่องเดียวกัน — ตรวจ inode เอง (FR-01 log rotation)
    stream_events  อ่านผ่าน SSH จาก pfSense — ใช้ `stdbuf -oL tail -n 0 -F`

FR-01:
    - อ่านเฉพาะบรรทัดใหม่ ไม่ replay ของเก่าตอน start
    - log rotation / truncate -> ตรวจเจอแล้วอ่านไฟล์ใหม่ต่อ
    - บรรทัดเสีย (JSON พัง / timestamp พัง / field ที่จำเป็นหาย) -> WARNING + ข้าม
      *** หนึ่งบรรทัดเสีย ≠ engine ทั้งระบบเสีย *** — generator ต้องไม่ตาย

FR-02:
    event_type = alert  -> normalize -> yield เข้า pipeline
    event_type = stats  -> on_stats(raw_event) -> ไม่ yield (STEP 9 เอาไปทำ health check)
    event_type อื่น      -> DEBUG log + ทิ้ง (ไม่เดา schema, ไม่นับเป็น alert)

*** reader ไม่ตัดสินอะไรทั้งสิ้น *** — severity คงเป็นเลขดิบของ Suricata (1=High,
2=Medium, 3=Low) ให้ Rule Engine เป็นคนตีความ (rules.yaml ใช้ raw severity)

SSH note (ของเดิมที่ยังคงไว้):
  1. Buffering delay  -> stdbuf -oL ฝั่ง pfSense + อ่านทีละบรรทัดด้วย readline
  2. Staircase output -> ssh -T (ไม่ขอ PTY) + stdin=DEVNULL
"""
import json
import logging
import os
import shlex
import subprocess
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# format ที่ Suricata เขียนแบบไม่มี ':' ในโซนเวลา (2026-09-19T16:20:01.123456+0700)
SURICATA_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"

EVENT_TYPE_ALERT = "alert"
EVENT_TYPE_STATS = "stats"

# field ที่ alert ต้องมี ไม่งั้นข้ามทั้ง event (FR-02)
REQUIRED_ALERT_FIELDS = ("timestamp", "src_ip", "signature", "severity")

DEFAULT_POLL_INTERVAL = 0.5


# ---------------------------------------------------------------- parsing
def parse_timestamp(value):
    """EVE timestamp -> aware UTC datetime; คืน None ถ้าอ่านไม่ได้

    *** ห้าม fallback เป็น datetime.now() *** — t_event ที่มั่วจะทำให้ latency metric
    (M1/M4) ผิดโดยไม่มีใครรู้ ข้าม event ไปเลยดีกว่า
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)          # +00:00 หรือ +0000
        except ValueError:
            try:
                dt = datetime.strptime(value, SURICATA_TS_FMT)
            except ValueError:
                return None
    else:
        return None

    if dt.tzinfo is None:                               # naive = ไม่รู้โซนเวลาจริง
        return None
    return dt.astimezone(timezone.utc)


def parse_line(line):
    """raw line -> dict; คืน None พร้อม WARNING ถ้า JSON เสีย (FR-01)"""
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        log.warning("ข้าม EVE line ที่ JSON เสีย: %s (%.120s)", exc, line)
        return None
    if not isinstance(event, dict):
        log.warning("ข้าม EVE line ที่ไม่ใช่ JSON object: %.120s", line)
        return None
    return event


def normalize(ev: dict):
    """EVE alert -> normalized event (11 field); คืน None ถ้าข้อมูลไม่ครบ

    field ที่จำเป็น: timestamp, src_ip, signature, severity
    field ที่เหลือหายได้ -> None
    """
    alert = ev.get("alert") or {}
    timestamp = parse_timestamp(ev.get("timestamp"))
    if timestamp is None:
        log.warning("ข้าม EVE alert ที่ timestamp ใช้ไม่ได้: %r", ev.get("timestamp"))
        return None

    normalized = {
        # เวลาที่ Suricata เห็น packet -> ใช้ใน Correlation window เสมอ
        "timestamp": timestamp,
        # เวลาที่ SEC01 ได้รับ -> ใช้วัด ingest latency (ไม่ใช่ตัดสิน window)
        "received_at": datetime.now(timezone.utc),
        "src_ip": ev.get("src_ip"),
        "src_port": ev.get("src_port"),
        "dest_ip": ev.get("dest_ip"),
        "dest_port": ev.get("dest_port"),
        "proto": ev.get("proto"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "severity": alert.get("severity"),      # Suricata: 1=High 2=Medium 3=Low (ดิบ)
        "event_type": ev.get("event_type", EVENT_TYPE_ALERT),
    }

    missing = [f for f in REQUIRED_ALERT_FIELDS if normalized.get(f) is None]
    if missing:
        log.warning("ข้าม EVE alert ที่ขาด field %s: src_ip=%s sid=%s",
                    missing, normalized.get("src_ip"), normalized.get("signature_id"))
        return None
    return normalized


def iter_events(lines, on_stats=None):
    """raw lines -> normalized alert events (generator)

    lines = iterable ของสตริง (ไฟล์ local, stdout ของ ssh, หรือ list ใน test)
    on_stats = callable(raw_stats_event) optional — extension point ของ STEP 9
    """
    for line in lines:
        event = parse_line(line)
        if event is None:
            continue

        event_type = event.get("event_type")
        if event_type == EVENT_TYPE_ALERT:
            normalized = normalize(event)
            if normalized is not None:
                yield normalized
        elif event_type == EVENT_TYPE_STATS:
            # ไม่เข้า correlation/risk — ส่งต่อให้ health check (FR-12) เท่านั้น
            if on_stats is not None:
                on_stats(event)
        else:
            log.debug("ข้าม EVE event_type ที่ไม่รองรับ: %s", event_type)


# ---------------------------------------------------------------- local transport
class LocalEveTail:
    """ตาม EVE JSON บนไฟล์ local แบบอ่านเฉพาะบรรทัดใหม่ (FR-01)

    - เริ่มที่ท้ายไฟล์ (from_start=False) -> ไม่ replay ของเก่า
    - ตรวจ log rotation ด้วย (st_ino, st_dev) และตรวจ truncate ด้วยขนาดไฟล์
    - `read_new_lines()` ไม่ block: คืนเท่าที่มีตอนนี้ ทำให้ทดสอบได้โดยไม่ต้องใช้ thread
    """

    def __init__(self, path, from_start=False, encoding="utf-8"):
        self.path = str(path)
        self.encoding = encoding
        self._fingerprint = None        # (st_ino, st_dev) ของไฟล์ที่กำลังตาม
        self._position = 0
        self._buffer = ""               # บรรทัดที่ยังเขียนไม่จบ (ไม่มี \n ปิดท้าย)
        if not from_start:
            self._seek_to_end()

    # ---- internal ----
    def _stat(self):
        try:
            return os.stat(self.path)
        except OSError:
            return None

    @staticmethod
    def _fingerprint_of(stat_result):
        return (stat_result.st_ino, stat_result.st_dev)

    def _seek_to_end(self):
        stat_result = self._stat()
        if stat_result is None:
            return
        self._fingerprint = self._fingerprint_of(stat_result)
        self._position = stat_result.st_size

    def _rotated(self, stat_result) -> bool:
        """ไฟล์ถูกแทนที่ (inode เปลี่ยน) หรือถูก truncate (ขนาดหดลง)"""
        if self._fingerprint is None:
            return True
        if self._fingerprint_of(stat_result) != self._fingerprint:
            return True
        return stat_result.st_size < self._position

    # ---- public ----
    def read_new_lines(self):
        """คืน list ของบรรทัดใหม่ที่เขียนจบแล้ว (ไม่มีก็คืน list ว่าง)"""
        stat_result = self._stat()
        if stat_result is None:                 # ไฟล์หาย (ระหว่าง rotate) — รอบหน้าค่อยว่า
            log.debug("ยังไม่พบไฟล์ EVE: %s", self.path)
            return []

        if self._rotated(stat_result):
            log.info("ตรวจพบ log rotation ของ %s — อ่านไฟล์ใหม่ตั้งแต่ต้น", self.path)
            self._fingerprint = self._fingerprint_of(stat_result)
            self._position = 0
            self._buffer = ""

        try:
            with open(self.path, "r", encoding=self.encoding, errors="replace") as f:
                f.seek(self._position)
                chunk = f.read()
                self._position = f.tell()
        except OSError as exc:
            log.warning("อ่านไฟล์ EVE ไม่สำเร็จ (%s): %s", self.path, exc)
            return []

        if not chunk:
            return []

        data = self._buffer + chunk
        lines = data.split("\n")
        self._buffer = lines.pop()              # ตัวสุดท้ายคือส่วนที่ยังไม่จบบรรทัด
        return [line for line in lines if line.strip()]

    def follow_lines(self, poll_interval=DEFAULT_POLL_INTERVAL, stop=None,
                     sleep=time.sleep):
        """generator ของบรรทัดใหม่แบบ real-time — วนจนกว่า stop() จะคืน True"""
        while stop is None or not stop():
            lines = self.read_new_lines()
            if lines:
                yield from lines
            else:
                sleep(poll_interval)


def stream_local_events(eve_path, on_stats=None, from_start=False,
                        poll_interval=DEFAULT_POLL_INTERVAL, stop=None,
                        sleep=time.sleep):
    """อ่าน EVE จากไฟล์บนเครื่องเดียวกัน -> normalized alert events"""
    tail = LocalEveTail(eve_path, from_start=from_start)
    return iter_events(tail.follow_lines(poll_interval=poll_interval, stop=stop,
                                         sleep=sleep),
                       on_stats=on_stats)


# ---------------------------------------------------------------- ssh transport
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


def stream_events(host, eve_path, on_stats=None):
    """อ่าน EVE จาก pfSense ผ่าน SSH -> normalized alert events (generator)

    host/eve_path เป็น required — ค่า config มาจาก caller (run_phase4) เท่านั้น
    ไฟล์นี้ไม่มี default ของ lab ใด ๆ
    """
    try:
        proc = subprocess.Popen(
            _ssh_cmd(host, eve_path),
            stdin=subprocess.DEVNULL,      # ssh ไม่แตะ TTY ของเรา
            stdout=subprocess.PIPE,
            stderr=None,                   # ให้ error ของ ssh โผล่บนจอตรงๆ
            text=True,
            bufsize=1,                     # line-buffered
        )
    except FileNotFoundError:
        log.error("ไม่พบคำสั่ง ssh บนเครื่องนี้ — อ่าน EVE จาก %s ไม่ได้", host)
        raise
    except OSError as exc:
        log.error("เปิด ssh ไปยัง %s ไม่สำเร็จ: %s", host, exc)
        raise

    log.info("เริ่มอ่าน EVE จาก %s:%s", host, eve_path)
    try:
        yield from iter_events(iter(proc.stdout.readline, ""), on_stats=on_stats)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # ssh ไม่ยอมจบ -> บังคับปิด ไม่ค้าง
            log.warning("ssh ไม่ตอบ terminate ภายใน 5s — kill")
            proc.kill()
            proc.wait(timeout=5)


if __name__ == "__main__":
    # ทดสอบ standalone: ITIS_PFSENSE_HOST/ITIS_EVE_PATH ต้องตั้งไว้ก่อน
    import sys

    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 3:
        sys.exit("usage: python -m security_engine.ingestion.eve_reader <host> <eve_path>")
    for e in stream_events(sys.argv[1], sys.argv[2]):
        lag = (e["received_at"] - e["timestamp"]).total_seconds()
        log.info("raw event %s %s -> %s sid=%s sev=%s ingest_lag=%.3fs",
                 e["timestamp"].isoformat(), e["src_ip"], e["dest_ip"],
                 e["signature_id"], e["severity"], lag)
