"""
tests/test_settings.py — STEP 1 Configuration Foundation (Blueprint NFR-01 / §3.3)

พิสูจน์ว่า configuration มี source of truth เดียวและพังให้รู้เมื่อค่าไม่ถูกต้อง:
    config/config.yaml -> load_settings() -> Settings (typed, validated)
    ITIS_EVE_PATH      -> override eve.path
    ITIS_PFSENSE_HOST  -> environment เท่านั้น (NFR-07)

ไม่แตะไฟล์จริงใน repo: ทุก test ที่แก้ค่าเขียน YAML ลง tmp_path
"""
import textwrap
from pathlib import Path

import pytest

from security_engine import settings as st
from security_engine.settings import ConfigError, load_settings

VALID_YAML = """\
system:
  db_path: "data/experiment.db"
  log_path: "logs/engine.log"

eve:
  path: "/var/log/suricata/suricata_test0/eve.json"

correlation:
  window_sec: 10
  min_events: 5

block:
  duration_sec: 300

health:
  check_interval_sec: 15
  stats_freshness_multiplier: 3

recovery:
  max_attempts: 3

risk:
  weight_set: "A"
"""

HOST = "admin@198.51.100.10"
ENV_EVE = "/var/log/suricata/suricata_env/eve.json"


def write_config(tmp_path, text=VALID_YAML) -> Path:
    f = tmp_path / "config.yaml"
    f.write_text(textwrap.dedent(text), encoding="utf-8")
    return f


@pytest.fixture
def clean_env(monkeypatch):
    """เริ่มทุก test จากสถานะที่ไม่มี env ทั้งสองตัว"""
    monkeypatch.delenv(st.ENV_PFSENSE_HOST, raising=False)
    monkeypatch.delenv(st.ENV_EVE_PATH, raising=False)
    return monkeypatch


# ---- 1. โหลด config ที่ถูกต้องได้ครบทุก section ----
def test_valid_config_loads(tmp_path, clean_env):
    s = load_settings(write_config(tmp_path))
    assert s.system.db_path == "data/experiment.db"
    assert s.system.log_path == "logs/engine.log"
    assert s.correlation.window_sec == 10
    assert s.correlation.min_events == 5
    assert s.block.duration_sec == 300
    assert s.health.check_interval_sec == 15
    assert s.health.stats_freshness_multiplier == 3
    assert s.recovery.max_attempts == 3
    assert s.risk.weight_set == "A"


# ---- 2. ค่าใน config.yaml ของ repo ตรงกับที่ Blueprint ล็อกไว้ ----
def test_repo_config_matches_blueprint_defaults(clean_env):
    s = load_settings()                       # ไฟล์จริงใน repo
    assert s.correlation.window_sec == 10     # §3.5 / FR-03
    assert s.correlation.min_events == 5
    assert s.block.duration_sec == 300        # §3.6 RULE-001
    assert s.health.check_interval_sec == 15  # FR-12
    assert s.health.stats_freshness_multiplier == 3
    assert s.recovery.max_attempts == 3       # FR-13
    assert s.risk.weight_set == "A"           # §3.5 Weight Set A


# ---- 3. ITIS_EVE_PATH override ค่าใน config ----
def test_eve_env_overrides_config(tmp_path, clean_env):
    clean_env.setenv(st.ENV_EVE_PATH, ENV_EVE)
    s = load_settings(write_config(tmp_path))
    assert s.eve.path == ENV_EVE
    assert s.require_eve_path() == ENV_EVE


def test_eve_from_config_when_env_absent(tmp_path, clean_env):
    s = load_settings(write_config(tmp_path))
    assert s.eve.path == "/var/log/suricata/suricata_test0/eve.json"


# ---- 4. env ว่าง/whitespace = ไม่ได้ตั้ง -> fallback ไป config ----
def test_blank_eve_env_falls_back_to_config(tmp_path, clean_env):
    clean_env.setenv(st.ENV_EVE_PATH, "")
    s = load_settings(write_config(tmp_path))
    assert s.eve.path == "/var/log/suricata/suricata_test0/eve.json"


def test_whitespace_eve_env_falls_back_to_config(tmp_path, clean_env):
    clean_env.setenv(st.ENV_EVE_PATH, "   ")
    s = load_settings(write_config(tmp_path))
    assert s.eve.path == "/var/log/suricata/suricata_test0/eve.json"


# ---- 5. ไม่มี eve path ทั้ง config และ env -> ConfigError ตอนเรียกใช้ ----
def test_missing_eve_path_raises_on_use(tmp_path, clean_env):
    s = load_settings(write_config(tmp_path, VALID_YAML.replace(
        '"/var/log/suricata/suricata_test0/eve.json"', '""')))
    assert s.eve.path == ""                   # โหลดผ่าน (ยังไม่ต้องใช้)
    with pytest.raises(ConfigError) as exc:
        s.require_eve_path()
    assert st.ENV_EVE_PATH in str(exc.value)


# ---- 6. ไฟล์ config หาย / YAML เสีย ----
def test_missing_config_file_raises(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_settings(tmp_path / "does_not_exist.yaml")
    assert "config" in str(exc.value)


def test_invalid_yaml_raises(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("system: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(f)


def test_yaml_not_mapping_raises(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(f)


# ---- 7. section / key หาย -> บอกชื่อที่หาย ----
def test_missing_section_raises_with_name(tmp_path):
    text = VALID_YAML.split("block:")[0] + VALID_YAML.split("duration_sec: 300\n")[1]
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, text))
    assert "block" in str(exc.value)


def test_missing_key_raises_with_path(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, VALID_YAML.replace(
            "  min_events: 5\n", "")))
    assert "correlation.min_events" in str(exc.value)


# ---- 8. range / type validation ----
@pytest.mark.parametrize("old,new,bad_key", [
    ("window_sec: 10", "window_sec: 0", "correlation.window_sec"),
    ("min_events: 5", "min_events: 0", "correlation.min_events"),
    ("duration_sec: 300", "duration_sec: 0", "block.duration_sec"),
    ("check_interval_sec: 15", "check_interval_sec: 0", "health.check_interval_sec"),
    ("stats_freshness_multiplier: 3", "stats_freshness_multiplier: 0",
     "health.stats_freshness_multiplier"),
    ("max_attempts: 3", "max_attempts: 0", "recovery.max_attempts"),
])
def test_out_of_range_values_rejected(tmp_path, old, new, bad_key):
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, VALID_YAML.replace(old, new)))
    assert bad_key in str(exc.value)


@pytest.mark.parametrize("old,new", [
    ("window_sec: 10", 'window_sec: "ten"'),
    ("min_events: 5", "min_events: 2.5"),
    ("max_attempts: 3", "max_attempts: true"),      # bool ต้องไม่ถูกนับเป็น int
])
def test_wrong_type_rejected(tmp_path, old, new):
    with pytest.raises(ConfigError):
        load_settings(write_config(tmp_path, VALID_YAML.replace(old, new)))


def test_empty_db_path_rejected(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, VALID_YAML.replace(
            '"data/experiment.db"', '""')))
    assert "system.db_path" in str(exc.value)


# ---- 9. weight set ต้องเป็น A/B/C เท่านั้น ----
@pytest.mark.parametrize("weight_set", ["A", "B", "C"])
def test_valid_weight_sets(tmp_path, clean_env, weight_set):
    s = load_settings(write_config(tmp_path, VALID_YAML.replace(
        'weight_set: "A"', f'weight_set: "{weight_set}"')))
    assert s.risk.weight_set == weight_set


@pytest.mark.parametrize("weight_set", ["D", "a", "", "AB"])
def test_invalid_weight_set_rejected(tmp_path, weight_set):
    with pytest.raises(ConfigError) as exc:
        load_settings(write_config(tmp_path, VALID_YAML.replace(
            'weight_set: "A"', f'weight_set: "{weight_set}"')))
    assert "weight_set" in str(exc.value)


# ---- 10. ITIS_PFSENSE_HOST: environment เท่านั้น (NFR-07) ----
def test_pfsense_host_from_env(tmp_path, clean_env):
    clean_env.setenv(st.ENV_PFSENSE_HOST, HOST)
    s = load_settings(write_config(tmp_path))
    assert s.pfsense_host() == HOST


def test_missing_pfsense_host_raises(tmp_path, clean_env):
    s = load_settings(write_config(tmp_path))
    with pytest.raises(ConfigError) as exc:
        s.pfsense_host()
    assert st.ENV_PFSENSE_HOST in str(exc.value)


def test_whitespace_pfsense_host_rejected(tmp_path, clean_env):
    clean_env.setenv(st.ENV_PFSENSE_HOST, "   ")
    s = load_settings(write_config(tmp_path))
    with pytest.raises(ConfigError):
        s.pfsense_host()


# ---- 11. config.yaml ไม่เก็บค่าเฉพาะเครื่อง (NFR-07) ----
def test_config_file_has_no_pfsense_host():
    text = st.DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")
    assert "192.168" not in text            # ไม่มี IP ของ lab หลุดเข้า repo
    assert "admin@" not in text


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
