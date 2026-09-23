"""
tests/test_assets.py — Lab Asset List Loader (config/assets.yaml)

policy (strict เหมือน allowlist): invalid IP -> raise, missing file -> raise, YAML เสีย -> raise
Loader แค่ supply set[str] ให้ SourceContextResolver — ไม่เดา role / ไม่คำนวณคะแนน
"""
import pytest

from security_engine.policy.assets import (
    load_assets, AssetsError, DEFAULT_ASSETS_PATH,
)


def _write(tmp_path, content):
    f = tmp_path / "assets.yaml"
    f.write_text(content, encoding="utf-8")
    return f


# ---- โหลดพื้นฐาน ----
def test_load_single_ipv4(tmp_path):
    f = _write(tmp_path, 'assets:\n  - "192.0.2.20"\n')
    assert load_assets(f) == {"192.0.2.20"}


def test_load_multiple_ips(tmp_path):
    f = _write(tmp_path, 'assets:\n  - "192.0.2.20"\n  - "192.0.2.21"\n')
    assert load_assets(f) == {"192.0.2.20", "192.0.2.21"}


def test_load_ipv6_canonicalized(tmp_path):
    f = _write(tmp_path, 'assets:\n  - "2001:DB8:0:0::1"\n')
    assert load_assets(f) == {"2001:db8::1"}


def test_whitespace_trimmed(tmp_path):
    f = _write(tmp_path, 'assets:\n  - "  192.0.2.20  "\n')
    assert load_assets(f) == {"192.0.2.20"}


def test_duplicates_deduped(tmp_path):
    f = _write(tmp_path, 'assets:\n  - "192.0.2.20"\n  - "192.0.2.20"\n')
    assert load_assets(f) == {"192.0.2.20"}


# ---- asset list ว่าง ----
def test_empty_list_returns_empty_set(tmp_path):
    assert load_assets(_write(tmp_path, "assets: []\n")) == set()


def test_null_value_returns_empty_set(tmp_path):
    assert load_assets(_write(tmp_path, "assets:\n")) == set()


def test_only_comments_returns_empty_set(tmp_path):
    assert load_assets(_write(tmp_path, "# nothing here\n")) == set()


# ---- policy strict ----
def test_invalid_ip_raises(tmp_path):
    f = _write(tmp_path, 'assets:\n  - "192.0.2.20"\n  - "999.999.999.999"\n')
    with pytest.raises(AssetsError):
        load_assets(f)


def test_garbage_entry_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(_write(tmp_path, 'assets:\n  - "web-server"\n'))


def test_non_string_entry_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(_write(tmp_path, "assets:\n  - 12345\n"))


def test_bool_entry_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(_write(tmp_path, "assets:\n  - true\n"))


def test_missing_file_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(tmp_path / "does_not_exist.yaml")


def test_malformed_yaml_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(_write(tmp_path, "assets: [unclosed\n"))


def test_wrong_top_level_type_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(_write(tmp_path, "- 192.0.2.20\n"))


def test_missing_key_raises(tmp_path):
    with pytest.raises(AssetsError) as exc:
        load_assets(_write(tmp_path, "allowlist: []\n"))
    assert "assets" in str(exc.value)


def test_wrong_value_type_raises(tmp_path):
    with pytest.raises(AssetsError):
        load_assets(_write(tmp_path, 'assets: "192.0.2.20"\n'))


# ---- ไฟล์จริงใน repo ----
def test_repo_assets_is_empty_by_design():
    """STEP 2B: lab ปัจจุบันไม่มี protected asset ที่ยืนยัน role ได้ -> ว่างโดยตั้งใจ"""
    assert DEFAULT_ASSETS_PATH.is_file()
    assert load_assets() == set()
