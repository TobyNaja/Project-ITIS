"""
security_engine/policy/rules_config.py — Decision Rules loader (Blueprint §3.6)

หน้าที่เดียว: อ่าน config/rules.yaml -> validate -> RuleSet
    rules.yaml -> load_rules() -> RuleSet(rules, default_action) -> RuleEngine(rules)

*** declarative เท่านั้น *** — condition เป็น field ที่ระบบรู้จักล่วงหน้า
ไม่มี eval()/exec() ไม่มี expression string ใน YAML

Policy (strict — safety config ต้องพังให้รู้ทันที):
    id/priority/action/condition หาย, action ไม่รู้จัก, severity ไม่รู้จัก,
    threshold ≤ 0, id ซ้ำ, priority ซ้ำ, condition field ที่ไม่รู้จัก
    -> raise RuleConfigError ทั้งหมด (ไม่ข้ามเงียบ)
"""
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_RULES_PATH = ROOT / "config" / "rules.yaml"

# ---- Action ที่ระบบรู้จัก (ต้องตรงกับ rule_engine) ----
MONITOR = "MONITOR"
ALERT = "ALERT"
BLOCK = "BLOCK"
NO_AUTO_BLOCK = "NO_AUTO_BLOCK"
VALID_ACTIONS = (MONITOR, ALERT, BLOCK, NO_AUTO_BLOCK)

# ---- ชื่อ severity -> เลข Suricata (เลขน้อย = รุนแรงกว่า) ----
#   0 = reserved ของโปรเจกต์สำหรับ custom critical signature
SEVERITY_NAMES = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ---- condition field ที่ evaluate ได้ (whitelist) ----
CONDITION_FIELDS = (
    "min_severity",            # ชื่อ severity ขั้นต่ำ เช่น "HIGH"
    "min_same_src_events",     # จำนวน event ขั้นต่ำของ source เดียวกัน
    "max_time_window_sec",     # ระยะเวลาของ pattern ต้องไม่เกินค่านี้
    "source_in_allowlist",     # true/false
)


class RuleConfigError(Exception):
    """rules.yaml หาย/ผิด format/ค่าไม่ถูกต้อง"""


@dataclass(frozen=True)
class Rule:
    id: str
    priority: int
    condition: dict
    action: str
    block_duration_sec: int = 0

    def matches(self, pattern, allowlisted: bool) -> bool:
        """เช็ค condition ทุกข้อของ rule นี้ (AND กันทั้งหมด)

        *** ห้ามใช้ risk_level เป็น condition *** — §3.5 ระบุว่า risk level ใช้เพื่อ
        dashboard/report ไม่ใช่ตัวตัดสิน block; rule ตัดสินจากข้อมูลของ pattern เอง
        """
        for field, expected in self.condition.items():
            if field == "source_in_allowlist":
                if allowlisted is not bool(expected):
                    return False
            elif field == "min_severity":
                severity = pattern.max_severity
                # เลขน้อย = รุนแรงกว่า -> "อย่างน้อย HIGH" คือ severity <= 1
                if severity is None or severity > SEVERITY_NAMES[expected]:
                    return False
            elif field == "min_same_src_events":
                if (pattern.event_count or 0) < expected:
                    return False
            elif field == "max_time_window_sec":
                window = pattern.window_seconds
                if window is None or window > expected:
                    return False
        return True


@dataclass(frozen=True)
class RuleSet:
    rules: tuple            # เรียงตาม priority แล้ว (น้อย = มาก่อน)
    default_action: str

    def __iter__(self):
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)


# ---------- validation helpers ----------
def _require(condition, message):
    if not condition:
        raise RuleConfigError(message)


def _positive_number(value, path):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuleConfigError(f"{path} ต้องเป็นตัวเลข ได้ {value!r}")
    if value <= 0:
        raise RuleConfigError(f"{path} ต้อง > 0 ได้ {value!r}")
    return value


def _parse_condition(raw, rule_id):
    _require(isinstance(raw, dict), f"rule {rule_id}: condition ต้องเป็น mapping")
    _require(raw, f"rule {rule_id}: condition ต้องไม่ว่าง")

    condition = {}
    for field, value in raw.items():
        if field not in CONDITION_FIELDS:
            raise RuleConfigError(
                f"rule {rule_id}: ไม่รู้จัก condition field {field!r} "
                f"(รองรับ {CONDITION_FIELDS})")
        if field == "source_in_allowlist":
            _require(isinstance(value, bool),
                     f"rule {rule_id}: source_in_allowlist ต้องเป็น true/false")
        elif field == "min_severity":
            _require(value in SEVERITY_NAMES,
                     f"rule {rule_id}: min_severity ต้องเป็นหนึ่งใน "
                     f"{tuple(SEVERITY_NAMES)} ได้ {value!r}")
        else:
            _positive_number(value, f"rule {rule_id}: {field}")
        condition[field] = value
    return condition


def _parse_rule(raw, index):
    _require(isinstance(raw, dict), f"rules[{index}] ต้องเป็น mapping")

    rule_id = raw.get("id")
    _require(isinstance(rule_id, str) and rule_id.strip(),
             f"rules[{index}] ขาด id")

    priority = raw.get("priority")
    _require(isinstance(priority, int) and not isinstance(priority, bool),
             f"rule {rule_id}: priority ต้องเป็นจำนวนเต็ม")
    _require(priority >= 1, f"rule {rule_id}: priority ต้อง >= 1")

    action = raw.get("action")
    _require(action in VALID_ACTIONS,
             f"rule {rule_id}: action ต้องเป็นหนึ่งใน {VALID_ACTIONS} ได้ {action!r}")

    condition = _parse_condition(raw.get("condition"), rule_id)

    duration = raw.get("block_duration_sec", 0)
    if action == BLOCK:
        # BLOCK ที่ไม่มี duration = block ค้างไม่มีกำหนดหรือหมดอายุทันที -> อันตราย
        _require("block_duration_sec" in raw,
                 f"rule {rule_id}: action BLOCK ต้องมี block_duration_sec")
        duration = int(_positive_number(duration, f"rule {rule_id}: block_duration_sec"))
    elif "block_duration_sec" in raw:
        raise RuleConfigError(
            f"rule {rule_id}: block_duration_sec ใช้ได้เฉพาะ action BLOCK")

    unknown = set(raw) - {"id", "priority", "condition", "action", "block_duration_sec"}
    _require(not unknown, f"rule {rule_id}: ไม่รู้จัก field {sorted(unknown)}")

    return Rule(id=rule_id.strip(), priority=priority, condition=condition,
                action=action, block_duration_sec=duration)


# ---------- loader ----------
def load_rules(path=DEFAULT_RULES_PATH) -> RuleSet:
    """อ่าน rules.yaml -> RuleSet ที่เรียงตาม priority แล้ว"""
    p = Path(path)
    if not p.is_file():
        raise RuleConfigError(f"ไม่พบไฟล์ rules: {p}")

    try:
        with p.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise RuleConfigError(f"rules ไม่ใช่ YAML ที่ถูกต้อง ({p}): {exc}") from exc

    _require(isinstance(data, dict), f"rules ต้องเป็น mapping ที่ระดับบนสุด ({p})")

    raw_rules = data.get("rules")
    _require(isinstance(raw_rules, list) and raw_rules,
             "rules.yaml ต้องมี key 'rules' เป็น list ที่ไม่ว่าง")

    default_action = data.get("default_action")
    _require(default_action in VALID_ACTIONS,
             f"default_action ต้องเป็นหนึ่งใน {VALID_ACTIONS} ได้ {default_action!r}")

    rules = [_parse_rule(raw, i) for i, raw in enumerate(raw_rules)]

    ids = [r.id for r in rules]
    _require(len(set(ids)) == len(ids), f"rule id ซ้ำ: {sorted(ids)}")

    priorities = [r.priority for r in rules]
    _require(len(set(priorities)) == len(priorities),
             f"priority ซ้ำ: {sorted(priorities)} — ลำดับการตัดสินต้อง deterministic")

    return RuleSet(rules=tuple(sorted(rules, key=lambda r: r.priority)),
                   default_action=default_action)
