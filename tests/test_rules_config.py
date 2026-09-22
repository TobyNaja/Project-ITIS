"""
tests/test_rules_config.py — rules.yaml loader + validation (Blueprint §3.6)

safety config ต้องพังให้รู้ทันที: id/priority/action/condition ผิด -> RuleConfigError
ไม่มี eval/expression — condition เป็น field ที่ระบบรู้จักล่วงหน้าเท่านั้น
"""
import textwrap

import pytest

from security_engine.policy.rules_config import (
    load_rules, RuleConfigError, RuleSet, Rule,
    DEFAULT_RULES_PATH, VALID_ACTIONS, SEVERITY_NAMES, CONDITION_FIELDS,
)

VALID = """\
rules:
  - id: "RULE-003"
    priority: 1
    condition:
      source_in_allowlist: true
    action: "NO_AUTO_BLOCK"

  - id: "RULE-001"
    priority: 2
    condition:
      min_severity: "HIGH"
      min_same_src_events: 5
      max_time_window_sec: 10
      source_in_allowlist: false
    action: "BLOCK"
    block_duration_sec: 300

default_action: "MONITOR"
"""


def write(tmp_path, text=VALID):
    f = tmp_path / "rules.yaml"
    f.write_text(textwrap.dedent(text), encoding="utf-8")
    return f


# ---- 1. repo rules.yaml ต้องโหลดได้และตรง §3.6 ----
def test_repo_rules_load():
    rules = load_rules()
    assert isinstance(rules, RuleSet)
    assert [r.id for r in rules] == ["RULE-003", "RULE-001", "RULE-002"]
    assert rules.default_action == "MONITOR"


def test_repo_rules_match_blueprint_conditions():
    by_id = {r.id: r for r in load_rules()}
    assert by_id["RULE-003"].condition == {"source_in_allowlist": True}
    assert by_id["RULE-003"].action == "NO_AUTO_BLOCK"
    assert by_id["RULE-001"].condition == {
        "min_severity": "HIGH", "min_same_src_events": 5,
        "max_time_window_sec": 10, "source_in_allowlist": False}
    assert by_id["RULE-001"].action == "BLOCK"
    assert by_id["RULE-001"].block_duration_sec == 300
    assert by_id["RULE-002"].condition == {
        "min_severity": "MEDIUM", "min_same_src_events": 5,
        "max_time_window_sec": 10}
    assert by_id["RULE-002"].action == "ALERT"


def test_default_path_points_to_repo_config():
    assert DEFAULT_RULES_PATH.name == "rules.yaml"
    assert DEFAULT_RULES_PATH.is_file()


# ---- 2. โหลดไฟล์ปกติ ----
def test_valid_file_loads(tmp_path):
    rules = load_rules(write(tmp_path))
    assert len(rules) == 2
    assert all(isinstance(r, Rule) for r in rules)


def test_rules_sorted_by_priority(tmp_path):
    rules = load_rules(write(tmp_path, VALID.replace(
        'priority: 1', 'priority: 9').replace('priority: 2', 'priority: 1')))
    assert [r.priority for r in rules] == [1, 9]
    assert [r.id for r in rules] == ["RULE-001", "RULE-003"]


# ---- 3. ไฟล์หาย / YAML เสีย / โครงสร้างผิด ----
def test_missing_file_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(tmp_path / "nope.yaml")


def test_malformed_yaml_raises(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("rules: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleConfigError):
        load_rules(f)


def test_not_mapping_raises(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(RuleConfigError):
        load_rules(f)


def test_missing_rules_key_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, 'default_action: "MONITOR"\n'))
    assert "rules" in str(exc.value)


def test_empty_rules_list_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, 'rules: []\ndefault_action: "MONITOR"\n'))


# ---- 4. field ที่จำเป็นหาย ----
def test_missing_id_raises(tmp_path):
    bad = """
rules:
  - priority: 1
    condition: {source_in_allowlist: true}
    action: "NO_AUTO_BLOCK"
default_action: "MONITOR"
"""
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, bad))
    assert "id" in str(exc.value)


def test_missing_priority_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace("    priority: 1\n", "")))
    assert "priority" in str(exc.value)


def test_missing_action_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace('    action: "NO_AUTO_BLOCK"\n', "")))


def test_missing_condition_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace(
            "    condition:\n      source_in_allowlist: true\n", "")))
    assert "condition" in str(exc.value)


# ---- 5. ค่าที่ไม่ถูกต้อง ----
def test_invalid_action_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace('"NO_AUTO_BLOCK"', '"DROP_EVERYTHING"')))
    assert "action" in str(exc.value)


def test_invalid_severity_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace('"HIGH"', '"SUPER_HIGH"')))
    assert "min_severity" in str(exc.value)


@pytest.mark.parametrize("bad", ["0", "-1"])
def test_non_positive_threshold_raises(tmp_path, bad):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace("min_same_src_events: 5",
                                                 f"min_same_src_events: {bad}")))


def test_priority_zero_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace("priority: 1", "priority: 0")))


def test_non_integer_priority_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace("priority: 1", 'priority: "first"')))


def test_unknown_condition_field_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace(
            "      source_in_allowlist: true",
            "      risk_level: 'HIGH'")))
    assert "risk_level" in str(exc.value)


def test_unknown_rule_field_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace(
            '    action: "NO_AUTO_BLOCK"',
            '    action: "NO_AUTO_BLOCK"\n    exec: "rm -rf /"')))


def test_source_in_allowlist_must_be_bool(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace(
            "source_in_allowlist: true", 'source_in_allowlist: "yes"')))


# ---- 6. duplicate ----
def test_duplicate_rule_id_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace('"RULE-001"', '"RULE-003"')))
    assert "id" in str(exc.value)


def test_duplicate_priority_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace("priority: 2", "priority: 1")))
    assert "priority" in str(exc.value)


# ---- 7. block_duration_sec ----
def test_block_without_duration_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace("    block_duration_sec: 300\n", "")))
    assert "block_duration_sec" in str(exc.value)


def test_duration_on_non_block_rule_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace(
            '    action: "NO_AUTO_BLOCK"',
            '    action: "NO_AUTO_BLOCK"\n    block_duration_sec: 300')))


def test_non_positive_duration_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace("block_duration_sec: 300",
                                                 "block_duration_sec: 0")))


# ---- 8. default_action ----
def test_invalid_default_action_raises(tmp_path):
    with pytest.raises(RuleConfigError) as exc:
        load_rules(write(tmp_path, VALID.replace('default_action: "MONITOR"',
                                                 'default_action: "PANIC"')))
    assert "default_action" in str(exc.value)


def test_missing_default_action_raises(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, VALID.replace('default_action: "MONITOR"\n', "")))


# ---- 9. constant ที่ contract ล็อกไว้ ----
def test_valid_actions_locked():
    assert set(VALID_ACTIONS) == {"MONITOR", "ALERT", "BLOCK", "NO_AUTO_BLOCK"}


def test_severity_names_match_suricata_convention():
    # เลขน้อย = รุนแรงกว่า; 0 = custom critical ของโปรเจกต์
    assert SEVERITY_NAMES == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def test_condition_fields_do_not_include_risk_level():
    assert "risk_level" not in CONDITION_FIELDS
    assert "risk_score" not in CONDITION_FIELDS


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
