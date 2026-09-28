"""
tests/test_eve_reader.py — STEP 7: EVE ingestion (FR-01 / FR-02)

    raw line -> parse -> classify -> normalize -> pipeline

FR-01: อ่านเฉพาะบรรทัดใหม่ · log rotation (inode) · บรรทัดเสียไม่ฆ่า generator
FR-02: alert -> yield · stats -> callback · event_type อื่น -> ignore

ไม่แตะ pfSense จริง: local tail ใช้ไฟล์ใน tmp_path, SSH ใช้ mock
"""
import json
import logging
import os
from datetime import datetime, timezone

import pytest

from security_engine.ingestion import eve_reader
from security_engine.ingestion.eve_reader import (
    LocalEveTail, iter_events, normalize, parse_line, parse_timestamp,
    stream_local_events, stream_events, _ssh_cmd,
    EVENT_TYPE_ALERT, EVENT_TYPE_STATS, REQUIRED_ALERT_FIELDS,
)

SRC = "198.51.100.77"


def alert_event(severity=1, src_ip=SRC, ts="2026-09-22T10:00:00.123456+0000",
                signature="ET SCAN Potential SSH Scan", sid=2001219, **extra):
    event = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 44321,
        "dest_ip": "192.0.2.10",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature_id": sid, "signature": signature, "severity": severity},
    }
    event.update(extra)
    return event


def stats_event(ts="2026-09-22T10:00:08.000000+0000"):
    return {"timestamp": ts, "event_type": "stats",
            "stats": {"uptime": 120, "decoder": {"pkts": 1000}}}


def line(event):
    return json.dumps(event) + "\n"


def write_lines(path, events):
    path.write_text("".join(line(e) for e in events), encoding="utf-8")


def append_lines(path, events):
    with path.open("a", encoding="utf-8") as f:
        f.write("".join(line(e) for e in events))


# ---------------------------------------------------------------- 1. JSON parsing
def test_valid_alert_line_parsed():
    event = parse_line(line(alert_event()))
    assert event["event_type"] == "alert"
    assert event["src_ip"] == SRC


def test_malformed_json_returns_none_with_warning(caplog):
    with caplog.at_level(logging.WARNING):
        assert parse_line('{"event_type": "alert", broken') is None
    assert any("JSON" in r.message for r in caplog.records)


def test_non_object_json_rejected(caplog):
    with caplog.at_level(logging.WARNING):
        assert parse_line("[1, 2, 3]") is None


def test_blank_line_ignored():
    assert parse_line("   \n") is None


# ---------------------------------------------------------------- 2. timestamp
@pytest.mark.parametrize("value", [
    "2026-09-22T10:00:00.123456+0000",      # Suricata แบบไม่มี ':' ในโซนเวลา
    "2026-09-22T10:00:00.123456+00:00",     # ISO-8601 มาตรฐาน
    "2026-09-22T17:00:00.123456+07:00",     # โซนเวลาอื่น
])
def test_supported_timestamp_formats(value):
    parsed = parse_timestamp(value)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0          # แปลงเป็น UTC แล้ว


def test_timestamp_converted_to_utc():
    parsed = parse_timestamp("2026-09-22T17:00:00.000000+07:00")
    assert parsed == datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", [None, "", "not-a-timestamp", 12345,
                                   "2026-09-22 10:00:00"])
def test_invalid_timestamp_returns_none(value):
    assert parse_timestamp(value) is None


def test_naive_timestamp_rejected():
    """ไม่มีโซนเวลา = ไม่รู้เวลาจริง -> ห้ามเดา"""
    assert parse_timestamp("2026-09-22T10:00:00.123456") is None


def test_no_fallback_to_now():
    """timestamp เสียต้องข้าม ไม่ใช่แทนด้วยเวลาปัจจุบัน (กัน M1/M4 เพี้ยน)"""
    assert normalize(alert_event(ts="broken")) is None


# ---------------------------------------------------------------- 3. normalize
def test_normalized_event_has_eleven_fields():
    normalized = normalize(alert_event())
    assert set(normalized) == {
        "timestamp", "received_at", "src_ip", "src_port", "dest_ip", "dest_port",
        "proto", "signature_id", "signature", "severity", "event_type"}


def test_normalized_values():
    normalized = normalize(alert_event(severity=2, sid=2010935))
    assert normalized["src_ip"] == SRC
    assert normalized["src_port"] == 44321
    assert normalized["dest_ip"] == "192.0.2.10"
    assert normalized["dest_port"] == 22
    assert normalized["proto"] == "TCP"
    assert normalized["signature_id"] == 2010935
    assert normalized["severity"] == 2
    assert normalized["event_type"] == EVENT_TYPE_ALERT
    assert normalized["timestamp"] == datetime(2026, 9, 22, 10, 0, 0, 123456,
                                               tzinfo=timezone.utc)
    assert normalized["received_at"].tzinfo is not None


@pytest.mark.parametrize("severity", [1, 2, 3])
def test_raw_suricata_severity_preserved(severity):
    """reader ไม่แปลงเป็น HIGH/MEDIUM/LOW — rules.yaml ใช้เลขดิบ"""
    assert normalize(alert_event(severity=severity))["severity"] == severity


@pytest.mark.parametrize("field", REQUIRED_ALERT_FIELDS)
def test_missing_required_field_is_skipped(field, caplog):
    event = alert_event()
    if field == "severity":
        event["alert"].pop("severity")
    elif field == "signature":
        event["alert"].pop("signature")
    else:
        event.pop(field)

    with caplog.at_level(logging.WARNING):
        assert normalize(event) is None
    assert caplog.records


def test_optional_fields_become_none():
    event = alert_event()
    for optional in ("src_port", "dest_ip", "dest_port", "proto"):
        event.pop(optional)
    event["alert"].pop("signature_id")

    normalized = normalize(event)
    assert normalized is not None
    assert normalized["src_port"] is None
    assert normalized["dest_ip"] is None
    assert normalized["dest_port"] is None
    assert normalized["proto"] is None
    assert normalized["signature_id"] is None


def test_alert_without_alert_object_is_skipped():
    event = alert_event()
    event.pop("alert")
    assert normalize(event) is None


# ---------------------------------------------------------------- 4. classification
def test_alert_is_yielded():
    events = list(iter_events([line(alert_event())]))
    assert len(events) == 1
    assert events[0]["src_ip"] == SRC


def test_stats_goes_to_callback_not_pipeline():
    seen = []
    events = list(iter_events([line(stats_event())], on_stats=seen.append))
    assert events == []                     # ไม่เข้า correlation/risk
    assert len(seen) == 1
    assert seen[0]["event_type"] == EVENT_TYPE_STATS
    assert seen[0]["stats"]["uptime"] == 120


def test_stats_without_callback_is_dropped():
    assert list(iter_events([line(stats_event())])) == []


@pytest.mark.parametrize("event_type", ["flow", "dns", "http", "fileinfo", "tls"])
def test_unsupported_event_types_ignored(event_type, caplog):
    raw = {"timestamp": "2026-09-22T10:00:00.000000+0000", "event_type": event_type}
    with caplog.at_level(logging.DEBUG):
        assert list(iter_events([line(raw)])) == []
    assert any("event_type" in r.message for r in caplog.records)


def test_unsupported_event_does_not_reach_stats_callback():
    seen = []
    list(iter_events([line({"timestamp": "2026-09-22T10:00:00.000000+0000",
                            "event_type": "dns"})], on_stats=seen.append))
    assert seen == []


# ---------------------------------------------------------------- 5. resilience
def test_bad_json_does_not_stop_reader():
    lines = [line(alert_event()), "{broken json", line(alert_event(src_ip="203.0.113.9"))]
    events = list(iter_events(lines))
    assert [e["src_ip"] for e in events] == [SRC, "203.0.113.9"]


def test_missing_timestamp_does_not_stop_reader():
    bad = alert_event()
    bad.pop("timestamp")
    events = list(iter_events([line(bad), line(alert_event(src_ip="203.0.113.9"))]))
    assert [e["src_ip"] for e in events] == ["203.0.113.9"]


def test_invalid_timestamp_does_not_stop_reader():
    events = list(iter_events([line(alert_event(ts="2026-13-45T99:99:99")),
                               line(alert_event(src_ip="203.0.113.9"))]))
    assert [e["src_ip"] for e in events] == ["203.0.113.9"]


def test_mixed_stream_produces_correct_outputs():
    """integration ของ parser: valid + malformed + stats + unsupported + valid"""
    seen = []
    lines = [
        line(alert_event(src_ip="198.51.100.1")),
        "not json at all",
        line(stats_event()),
        line({"timestamp": "2026-09-22T10:00:00.000000+0000", "event_type": "flow"}),
        line(alert_event(src_ip="198.51.100.2")),
    ]
    events = list(iter_events(lines, on_stats=seen.append))
    assert [e["src_ip"] for e in events] == ["198.51.100.1", "198.51.100.2"]
    assert len(seen) == 1


# ---------------------------------------------------------------- 6. local tail
def test_existing_lines_are_not_replayed(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [alert_event(src_ip="198.51.100.1")])

    tail = LocalEveTail(path)                       # เริ่มที่ท้ายไฟล์
    assert tail.read_new_lines() == []

    append_lines(path, [alert_event(src_ip="198.51.100.2")])
    lines = tail.read_new_lines()
    assert len(lines) == 1
    assert "198.51.100.2" in lines[0]


def test_from_start_reads_existing_lines(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [alert_event(), alert_event()])
    assert len(LocalEveTail(path, from_start=True).read_new_lines()) == 2


def test_only_new_lines_each_call(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [])
    tail = LocalEveTail(path)

    append_lines(path, [alert_event(src_ip="198.51.100.1")])
    assert len(tail.read_new_lines()) == 1
    assert tail.read_new_lines() == []              # ไม่มีของใหม่ -> ว่าง

    append_lines(path, [alert_event(), alert_event()])
    assert len(tail.read_new_lines()) == 2


def test_partial_line_is_buffered_until_complete(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("", encoding="utf-8")
    tail = LocalEveTail(path)

    with path.open("a", encoding="utf-8") as f:     # เขียนครึ่งบรรทัด
        f.write('{"event_type": "alert", "src')
    assert tail.read_new_lines() == []              # ยังไม่จบบรรทัด -> ยังไม่คืน

    with path.open("a", encoding="utf-8") as f:
        f.write('_ip": "198.51.100.9"}\n')
    lines = tail.read_new_lines()
    assert len(lines) == 1
    assert json.loads(lines[0])["src_ip"] == "198.51.100.9"


def test_missing_file_returns_empty(tmp_path):
    tail = LocalEveTail(tmp_path / "not-there.json")
    assert tail.read_new_lines() == []


# ---------------------------------------------------------------- 7. rotation
def test_rotation_detected_by_inode(tmp_path, caplog):
    path = tmp_path / "eve.json"
    write_lines(path, [alert_event(src_ip="198.51.100.1")])
    tail = LocalEveTail(path)

    append_lines(path, [alert_event(src_ip="198.51.100.2")])
    assert len(tail.read_new_lines()) == 1

    # log rotate: ย้ายของเดิมออก แล้วสร้างไฟล์ใหม่ชื่อเดิม (inode เปลี่ยน)
    old_inode = os.stat(path).st_ino
    os.replace(path, tmp_path / "eve.json.1")
    write_lines(path, [alert_event(src_ip="198.51.100.3")])
    assert os.stat(path).st_ino != old_inode

    with caplog.at_level(logging.INFO):
        lines = tail.read_new_lines()
    assert len(lines) == 1
    assert "198.51.100.3" in lines[0]
    assert any("rotation" in r.message for r in caplog.records)


def test_reader_continues_after_rotation(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [])
    tail = LocalEveTail(path)

    append_lines(path, [alert_event(src_ip="198.51.100.1")])
    tail.read_new_lines()

    os.replace(path, tmp_path / "eve.json.1")
    write_lines(path, [alert_event(src_ip="198.51.100.2")])
    tail.read_new_lines()

    append_lines(path, [alert_event(src_ip="198.51.100.3")])   # เขียนต่อบนไฟล์ใหม่
    lines = tail.read_new_lines()
    assert len(lines) == 1
    assert "198.51.100.3" in lines[0]


def test_truncation_is_treated_as_rotation(tmp_path):
    """copytruncate: inode เดิมแต่ไฟล์ถูกล้าง -> ต้องอ่านตั้งแต่ต้นใหม่"""
    path = tmp_path / "eve.json"
    write_lines(path, [alert_event(src_ip="198.51.100.1")])
    tail = LocalEveTail(path)
    append_lines(path, [alert_event(src_ip="198.51.100.2")])
    tail.read_new_lines()

    write_lines(path, [alert_event(src_ip="198.51.100.9")])     # truncate + เขียนใหม่
    lines = tail.read_new_lines()
    assert len(lines) == 1
    assert "198.51.100.9" in lines[0]


def test_malformed_line_during_rotation_does_not_stop_stream(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [])
    tail = LocalEveTail(path)

    with path.open("a", encoding="utf-8") as f:
        f.write("half-written-line-from-rotation\n")
    append_lines(path, [alert_event(src_ip="198.51.100.1")])

    events = list(iter_events(tail.read_new_lines()))
    assert [e["src_ip"] for e in events] == ["198.51.100.1"]


# ---------------------------------------------------------------- 8. follow / stream
def test_follow_lines_stops_via_stop_callable(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [])
    append_lines(path, [alert_event(src_ip="198.51.100.1")])

    tail = LocalEveTail(path, from_start=True)
    ticks = {"n": 0}

    def stop():
        ticks["n"] += 1
        return ticks["n"] > 3

    lines = list(tail.follow_lines(stop=stop, sleep=lambda _: None))
    assert len(lines) == 1


def test_stream_local_events_end_to_end(tmp_path):
    path = tmp_path / "eve.json"
    write_lines(path, [alert_event(src_ip="198.51.100.1"), stats_event(),
                       alert_event(src_ip="198.51.100.2")])
    seen = []
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return calls["n"] > 2

    events = list(stream_local_events(path, on_stats=seen.append, from_start=True,
                                      stop=stop, sleep=lambda _: None))
    assert [e["src_ip"] for e in events] == ["198.51.100.1", "198.51.100.2"]
    assert len(seen) == 1


# ---------------------------------------------------------------- 9. ssh transport
def test_ssh_command_construction():
    cmd = _ssh_cmd("admin@198.51.100.10", "/var/log/suricata/x/eve.json")
    assert cmd[0] == "ssh"
    assert "-T" in cmd                                   # ไม่ขอ PTY
    assert "BatchMode=yes" in cmd
    assert cmd[-2] == "admin@198.51.100.10"
    assert "tail -n 0 -F" in cmd[-1]                     # ไม่ replay ของเก่า
    assert "stdbuf -oL" in cmd[-1]                       # กัน buffering delay


def test_ssh_command_quotes_path():
    cmd = _ssh_cmd("h", "/var/log/suricata/weird path/eve.json")
    assert "'/var/log/suricata/weird path/eve.json'" in cmd[-1]


def test_stream_events_requires_host_and_path():
    with pytest.raises(TypeError):
        stream_events()


def test_no_lab_defaults_left_in_module():
    """ค่า lab ที่เคย hardcode ต้องไม่เหลืออยู่ในไฟล์นี้"""
    assert not hasattr(eve_reader, "PFSENSE_HOST")
    assert not hasattr(eve_reader, "EVE_PATH")


def test_stream_events_uses_transport_and_parser(monkeypatch):
    """mock subprocess: stdout ของ ssh -> parser เดียวกับ local"""
    lines = [line(alert_event(src_ip="198.51.100.1")), "broken",
             line(stats_event()), line(alert_event(src_ip="198.51.100.2")), ""]
    seen = []
    terminated = {"called": False}

    class FakeProc:
        def __init__(self):
            self.stdout = iter(lines)
            self.stdout = type("S", (), {"readline": lambda s: next(iter_lines, "")})()

        def terminate(self):
            terminated["called"] = True

        def wait(self, timeout=None):
            return 0

    iter_lines = iter(lines)
    monkeypatch.setattr(eve_reader.subprocess, "Popen", lambda *a, **k: FakeProc())

    events = list(stream_events("h", "/tmp/eve.json", on_stats=seen.append))

    assert [e["src_ip"] for e in events] == ["198.51.100.1", "198.51.100.2"]
    assert len(seen) == 1
    assert terminated["called"] is True


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
