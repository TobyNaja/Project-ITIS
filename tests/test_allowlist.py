"""
tests/test_allowlist.py — Allowlist Loader (config/allowlist.yaml)

policy (strict): invalid IP -> raise, missing file -> raise, YAML เสีย -> raise
Loader แค่ supply set[str] ให้ชั้นที่ตัดสิน — ไม่ตัดสิน block เอง
"""
from datetime import datetime, timedelta, timezone

import pytest

from security_engine.models import CorrelationPattern
from security_engine.policy.allowlist import (
    load_allowlist, AllowlistError, DEFAULT_ALLOWLIST_PATH,
)
from security_engine.policy.rule_engine import RuleEngine, NO_AUTO_BLOCK, BLOCK
from security_engine.policy.rules_config import load_rules

T0 = datetime(2026, 9, 22, 10, 0, 0, tzinfo=timezone.utc)


def _write(tmp_path, content):
    f = tmp_path / "allowlist.yaml"
    f.write_text(content, encoding="utf-8")
    return f


class FakeRisk:
    def __init__(self, src_ip, risk_level="HIGH"):
        self.src_ip = src_ip
        self.risk_level = risk_level
        self.risk_score = 79.5


def pattern(src, severity=1, count=5, window=4.2):
    return CorrelationPattern(
        src_ip=src, window_start=T0, window_end=T0 + timedelta(seconds=window),
        event_count=count, max_severity=severity)


# ---- โหลดพื้นฐาน ----
def test_load_single_ipv4(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "192.168.2.10"\n')
    assert load_allowlist(f) == {"192.168.2.10"}


def test_load_multiple_ips(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "192.168.2.10"\n  - "10.0.0.1"\n  - "172.16.0.5"\n')
    assert load_allowlist(f) == {"192.168.2.10", "10.0.0.1", "172.16.0.5"}


def test_load_ipv6(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "::1"\n  - "2001:db8::1"\n')
    assert load_allowlist(f) == {"::1", "2001:db8::1"}


def test_inline_yaml_list(tmp_path):
    f = _write(tmp_path, 'allowlist: ["192.168.2.10", "10.0.0.1"]\n')
    assert load_allowlist(f) == {"192.168.2.10", "10.0.0.1"}


def test_whitespace_trimmed(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "  192.168.2.10  "\n')
    assert load_allowlist(f) == {"192.168.2.10"}


def test_duplicates_deduped(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "192.168.2.10"\n  - "192.168.2.10"\n')
    assert load_allowlist(f) == {"192.168.2.10"}


def test_comments_ignored(tmp_path):
    f = _write(tmp_path, '# gateway ห้าม block\nallowlist:\n  - "192.168.2.10"  # DNS\n')
    assert load_allowlist(f) == {"192.168.2.10"}


# ---- allowlist ว่าง ----
def test_empty_list_returns_empty_set(tmp_path):
    assert load_allowlist(_write(tmp_path, "allowlist: []\n")) == set()


def test_null_value_returns_empty_set(tmp_path):
    assert load_allowlist(_write(tmp_path, "allowlist:\n")) == set()


def test_only_comments_returns_empty_set(tmp_path):
    assert load_allowlist(_write(tmp_path, "# nothing here\n")) == set()


# ---- policy strict ----
def test_invalid_ip_raises(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "192.168.2.10"\n  - "999.999.999.999"\n')
    with pytest.raises(AllowlistError):
        load_allowlist(f)


def test_garbage_entry_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(_write(tmp_path, 'allowlist:\n  - "not-an-ip"\n'))


def test_non_string_entry_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(_write(tmp_path, "allowlist:\n  - 12345\n"))


def test_missing_file_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(tmp_path / "does_not_exist.yaml")


def test_malformed_yaml_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(_write(tmp_path, "allowlist: [unclosed\n"))


def test_wrong_top_level_type_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(_write(tmp_path, "- 192.168.2.10\n"))


def test_missing_key_raises(tmp_path):
    with pytest.raises(AllowlistError) as exc:
        load_allowlist(_write(tmp_path, "protected: []\n"))
    assert "allowlist" in str(exc.value)


def test_wrong_value_type_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(_write(tmp_path, 'allowlist: "192.168.2.10"\n'))


# ---- ไฟล์จริงใน repo ----
def test_repo_allowlist_is_empty_by_default():
    assert DEFAULT_ALLOWLIST_PATH.is_file()
    assert load_allowlist() == set()


# ---- integration: loader -> set -> RuleEngine ----
def test_loaded_allowlist_feeds_rule_engine(tmp_path):
    f = _write(tmp_path, 'allowlist:\n  - "192.168.2.10"\n')
    eng = RuleEngine(load_rules(), allowlist=load_allowlist(f))

    # source ที่ allowlist -> NO_AUTO_BLOCK แม้เข้าเกณฑ์ block เต็ม
    d = eng.decide(FakeRisk("192.168.2.10", "CRITICAL"),
                   pattern("192.168.2.10", severity=1, count=9, window=1.0))
    assert d.action == NO_AUTO_BLOCK

    # source ที่ไม่ได้ allowlist -> ยัง block ตามปกติ
    d2 = eng.decide(FakeRisk("5.6.7.8"), pattern("5.6.7.8", severity=1))
    assert d2.action == BLOCK
