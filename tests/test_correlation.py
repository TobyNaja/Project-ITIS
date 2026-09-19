from datetime import datetime, timedelta, timezone
from security_engine.correlation.engine import CorrelationEngine

def make_event(ip, seconds_offset=0, sid=1000001):
    base_time = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
    event_time = base_time + timedelta(seconds=seconds_offset)
    return {
        "timestamp": event_time.isoformat(),
        "src_ip": ip,
        "dest_ip": "192.168.1.1",
        "signature_id": sid,
        "severity": 3,
    }

# Test 1: 4 events ภายใน 10s -> ต้องไม่ MATCH
def test_fewer_than_min_events_no_match():
    engine = CorrelationEngine(window_seconds=10, min_events=5)
    match = None
    for i in range(4):
        match = engine.process(make_event("192.168.2.10", seconds_offset=i))
    assert match is None

# Test 2: 5 events ภายใน 10s -> ต้อง MATCH
def test_min_events_matched():
    engine = CorrelationEngine(window_seconds=10, min_events=5)
    match = None
    for i in range(5):
        match = engine.process(make_event("192.168.2.10", seconds_offset=i))
    assert match is not None
    assert match["src_ip"] == "192.168.2.10"
    assert match["event_count"] == 5
    assert match["window_seconds"] == 4.0

# Test 3: Sliding Window Expiry -> เมื่อ Event ที่ 5 มาถึง Event แรกหลุดออกจาก 10-second window (เหลือ 4 events) ต้องไม่ MATCH
def test_sliding_window_expiry_no_match():
    engine = CorrelationEngine(window_seconds=10, min_events=5)
    match = None
    # ยิง 5 events เว้นระยะห่าง event ละ 3 วินาที (0s, 3s, 6s, 9s, 12s)
    # ณ t=12s Event ที่ 0s จะถูก popleft() ออก ทำให้ใน bucket เหลือเพียง 4 events
    for i in range(5):
        match = engine.process(
            make_event("192.168.2.10", seconds_offset=i * 3)
        )
    assert match is None

# Test 4: คนละ Source IP -> ต้องแยก Bucket ไม่นำมารวมกัน
def test_source_separation():
    engine = CorrelationEngine(window_seconds=10, min_events=5)

    # IP_A ยิง 3 events, IP_B ยิง 3 events สลับกัน
    for i in range(3):
        engine.process(make_event("192.168.2.10", seconds_offset=i))
        engine.process(make_event("192.168.2.20", seconds_offset=i))

    # ตรวจสอบ Internal State ว่าแต่ละ IP ถูกแยก Bucket ออกจากกัน
    assert len(engine.events["192.168.2.10"]) == 3
    assert len(engine.events["192.168.2.20"]) == 3


# Test 5: Cooldown Suppression -> Event ที่ 6, 7 ยิงติดกันต้องไม่ MATCH ซ้ำ
def test_cooldown_suppression():
    engine = CorrelationEngine(
        window_seconds=10, min_events=5, cooldown_seconds=10
    )

    # ยิง 5 events แรก -> เกิด MATCH
    for i in range(5):
        match = engine.process(make_event("192.168.2.10", seconds_offset=i))
    assert match is not None

    # ยิง event ที่ 6 และ 7 ที่วินาทีที่ 5 และ 6 (ยังอยู่ใน Cooldown 10s) -> ต้องคืนค่า None
    match_6 = engine.process(make_event("192.168.2.10", seconds_offset=5))
    match_7 = engine.process(make_event("192.168.2.10", seconds_offset=6))

    assert match_6 is None
    assert match_7 is None