"""
tests/test_allowlist.py — Phase 10 Allowlist Loader

policy (strict): invalid IP -> raise, missing file -> raise
Loader แค่ supply set ให้ RuleEngine — ไม่ตัดสิน block เอง
"""
import pytest

from security_engine.policy.allowlist import load_allowlist, AllowlistError
from security_engine.policy.rule_engine import RuleEngine, NO_AUTO_BLOCK, BLOCK


def _write(tmp_path, content):
    f = tmp_path / "allowlist.txt"
    f.write_text(content, encoding="utf-8")
    return f


class FakeRisk:
    def __init__(self, src_ip, risk_level):
        self.src_ip = src_ip
        self.risk_level = risk_level


def corr(count=5, window=4.2):
    return {"event_count": count, "window_seconds": window}


# ---- โหลดพื้นฐาน ----
def test_load_single_ipv4(tmp_path):
    f = _write(tmp_path, "192.168.2.10\n")
    assert load_allowlist(f) == {"192.168.2.10"}


def test_load_multiple_ips(tmp_path):
    f = _write(tmp_path, "192.168.2.10\n10.0.0.1\n172.16.0.5\n")
    assert load_allowlist(f) == {"192.168.2.10", "10.0.0.1", "172.16.0.5"}


def test_load_ipv6(tmp_path):
    f = _write(tmp_path, "::1\n2001:db8::1\n")
    assert load_allowlist(f) == {"::1", "2001:db8::1"}


# ---- การข้าม/จัดรูปแบบ ----
def test_blank_lines_skipped(tmp_path):
    f = _write(tmp_path, "192.168.2.10\n\n\n10.0.0.1\n\n")
    assert load_allowlist(f) == {"192.168.2.10", "10.0.0.1"}


def test_comment_lines_skipped(tmp_path):
    f = _write(tmp_path, "# gateway ห้าม block\n192.168.2.10\n# another\n")
    assert load_allowlist(f) == {"192.168.2.10"}


def test_inline_comment_stripped(tmp_path):
    f = _write(tmp_path, "192.168.2.10   # DNS server\n")
    assert load_allowlist(f) == {"192.168.2.10"}


def test_whitespace_trimmed(tmp_path):
    f = _write(tmp_path, "   192.168.2.10   \n\t10.0.0.1\t\n")
    assert load_allowlist(f) == {"192.168.2.10", "10.0.0.1"}


def test_duplicates_deduped(tmp_path):
    f = _write(tmp_path, "192.168.2.10\n192.168.2.10\n192.168.2.10\n")
    assert load_allowlist(f) == {"192.168.2.10"}


# ---- policy strict ----
def test_invalid_ip_raises(tmp_path):
    f = _write(tmp_path, "192.168.2.10\n999.999.999.999\n")
    with pytest.raises(AllowlistError):
        load_allowlist(f)


def test_garbage_line_raises(tmp_path):
    f = _write(tmp_path, "not-an-ip\n")
    with pytest.raises(AllowlistError):
        load_allowlist(f)


def test_missing_file_raises(tmp_path):
    with pytest.raises(AllowlistError):
        load_allowlist(tmp_path / "does_not_exist.txt")


def test_empty_file_returns_empty_set(tmp_path):
    f = _write(tmp_path, "")
    assert load_allowlist(f) == set()


def test_only_comments_returns_empty_set(tmp_path):
    f = _write(tmp_path, "# just comments\n# nothing else\n")
    assert load_allowlist(f) == set()


# ---- integration กับ RuleEngine (loader -> set -> RuleEngine) ----
def test_loaded_allowlist_feeds_rule_engine(tmp_path):
    f = _write(tmp_path, "192.168.2.10\n")
    allow = load_allowlist(f)
    eng = RuleEngine(allowlist=allow, min_events=5, max_window=10.0)

    # source ที่ allowlist -> NO_AUTO_BLOCK แม้เข้าเกณฑ์ block เต็ม
    d = eng.decide(FakeRisk("192.168.2.10", "CRITICAL"), corr(9, 1.0))
    assert d.action == NO_AUTO_BLOCK

    # source ที่ไม่ได้ allowlist -> ยัง block ตามปกติ
    d2 = eng.decide(FakeRisk("5.6.7.8", "HIGH"), corr(5, 4.2))
    assert d2.action == BLOCK