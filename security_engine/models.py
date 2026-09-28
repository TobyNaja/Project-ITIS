"""
security_engine/models.py — Shared data contracts (Blueprint §3.3)

dataclass ที่หลาย layer ใช้ร่วมกัน — ไม่มี logic ของ phase ไหนอยู่ในนี้
    CorrelationEngine -> CorrelationPattern -> RiskModel -> RiskResult -> RuleEngine
    SourceContextResolver -> SourceContext -> RiskModel (factor C)

*** field ของ CorrelationPattern ตรงกับตาราง correlated_patterns (§3.4) ***
เพื่อให้ persistence ใน STEP 5 เขียนลง DB ได้โดยไม่ต้องแปลงชื่อ
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

# anchor สำหรับ pattern ที่มาจาก dict เก่า (ไม่มี timestamp จริง) — ดู from_dict()
_LEGACY_ANCHOR = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class SourceContext:
    """บริบทของ source IP ที่ Risk Model ใช้คำนวณ factor C
    resolve มาจากภายนอก (allowlist + asset list) — Risk Model ไม่โหลดไฟล์เอง"""
    allowlisted: bool = False
    known_asset: bool = False


@dataclass(frozen=True)
class CorrelationPattern:
    """pattern ที่ correlate แล้ว 1 ชุด (source IP เดียว, window เดียว)

    max_severity = severity ที่ **รุนแรงที่สุด** ของ pattern
        Suricata ใช้เลขน้อย = รุนแรงกว่า (1=HIGH, 2=MEDIUM, 3=LOW)
        ดังนั้นค่านี้คือ min() ของตัวเลข — ชื่อ field ยึดตาม §3.4 schema
    """
    src_ip: str
    window_start: datetime
    window_end: datetime
    event_count: int
    max_severity: int = None
    events: tuple = field(default_factory=tuple)

    @property
    def window_seconds(self) -> float:
        """ระยะเวลาจริงของ pattern (derived) — ไม่ใช่ขนาด window ที่ config ไว้"""
        return (self.window_end - self.window_start).total_seconds()

    # ---- compatibility shim (ชั่วคราวจนถึง STEP 3/5) ----
    # RuleEngine และ test เดิมยังเข้าถึงแบบ dict (correlation.get("event_count"))
    # ให้ pattern ตอบได้ทั้งสองแบบ จะได้ไม่ต้องแก้ rule engine ใน STEP นี้
    _DICT_KEYS = ("src_ip", "event_count", "window_seconds", "events",
                  "max_severity", "window_start", "window_end")

    def get(self, key, default=None):
        if key in self._DICT_KEYS:
            return getattr(self, key)
        return default

    def __getitem__(self, key):
        if key in self._DICT_KEYS:
            return getattr(self, key)
        raise KeyError(key)

    @classmethod
    def from_dict(cls, data):
        """สร้าง pattern จาก dict แบบเก่า {src_ip, event_count, window_seconds, events}

        ใช้กับ fake correlator ใน test และโค้ดที่ยังไม่ได้ย้าย — ถ้า dict ไม่มี
        timestamp จริง จะ anchor window ที่ epoch แล้วคง **ระยะเวลา** ไว้ให้ถูก
        (factor T สนใจแค่ระยะเวลา ไม่สนใจว่า pattern เกิดเมื่อไหร่)
        """
        if isinstance(data, cls):
            return data
        events = tuple(data.get("events", ()))
        start = data.get("window_start")
        end = data.get("window_end")
        if start is None or end is None:
            start = _LEGACY_ANCHOR
            end = _LEGACY_ANCHOR.fromtimestamp(
                _LEGACY_ANCHOR.timestamp() + float(data.get("window_seconds", 0.0)),
                tz=timezone.utc)
        severities = [e.get("severity") for e in events
                      if isinstance(e, dict) and e.get("severity") is not None]
        return cls(
            src_ip=data.get("src_ip", "unknown"),
            window_start=start,
            window_end=end,
            event_count=data.get("event_count", len(events)),
            max_severity=data.get("max_severity",
                                  min(severities) if severities else None),
            events=events,
        )
