"""
security_engine/logging_config.py — Logging setup (Blueprint NFR-03)

    config.yaml (system.log_path / system.log_level) -> configure_logging() -> logs/engine.log

NFR-03: ใช้ logging module — INFO ขึ้นไปลงไฟล์, DEBUG เปิดได้จาก config
NFR-04: timestamp ของ log เป็น UTC ISO8601 เหมือน field เวลาอื่นในระบบ

*** ไม่มี framework ใหม่ *** — ใช้ logging ของ stdlib ตรง ๆ
entry point เป็นคนเรียก configure_logging() ครั้งเดียวตอน start
โมดูลอื่นใช้แค่ `log = logging.getLogger(__name__)` ไม่ตั้งค่าเอง
"""
import logging
import time
from pathlib import Path

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
DEFAULT_LOG_LEVEL = "INFO"

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s :: %(message)s"
# NFR-04: เวลาทุกจุดเป็น UTC — log ก็ต้องเป็น UTC ไม่ใช่เวลาเครื่อง
# *** ห้ามใช้ %z ***: time.strftime กับ struct_time จาก gmtime จะพิมพ์ offset ของ
# "เครื่อง" (เช่น +0700) ต่อท้ายเวลาที่เป็น UTC อยู่แล้ว -> อ่านแล้วเข้าใจผิดทันที
# ใช้ Z ปิดท้ายแทนเพื่อบอกว่าเป็น UTC ตรง ๆ
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_HANDLER_NAME = "itis-engine-file"


def _utc_formatter() -> logging.Formatter:
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    formatter.converter = time.gmtime
    return formatter


def configure_logging(log_path, level=DEFAULT_LOG_LEVEL, console=True):
    """ตั้งค่า root logger ให้เขียนลงไฟล์ (+ console) — idempotent

    เรียกซ้ำจะไม่ทำให้ log ซ้ำบรรทัด เพราะ handler เดิมถูกแทนที่
    """
    level_name = str(level).upper()
    if level_name not in VALID_LOG_LEVELS:
        raise ValueError(
            f"log level ต้องเป็นหนึ่งใน {VALID_LOG_LEVELS} ได้ {level!r}")

    path = Path(log_path)
    if path.parent and str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level_name)

    # ถอด handler ที่เราเคยติดไว้ออกก่อน (กัน log ซ้ำเมื่อเรียกซ้ำ)
    for handler in list(root.handlers):
        if getattr(handler, "name", None) in (_HANDLER_NAME, _HANDLER_NAME + "-console"):
            root.removeHandler(handler)
            handler.close()

    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.name = _HANDLER_NAME
    file_handler.setLevel(level_name)
    file_handler.setFormatter(_utc_formatter())
    root.addHandler(file_handler)

    if console:
        stream_handler = logging.StreamHandler()
        stream_handler.name = _HANDLER_NAME + "-console"
        stream_handler.setLevel(level_name)
        stream_handler.setFormatter(_utc_formatter())
        root.addHandler(stream_handler)

    return root


def configure_from_settings(settings, console=True):
    """สะดวกสำหรับ entry point: อ่าน log_path/log_level จาก Settings"""
    return configure_logging(settings.system.log_path,
                             level=settings.system.log_level,
                             console=console)
