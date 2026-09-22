"""
security_engine/policy/allowlist.py — Allowlist Loader (Blueprint §3.3)

หน้าที่เดียว: อ่าน config/allowlist.yaml -> คืน set ของ IP (canonical string)
    allowlist.yaml -> load_allowlist() -> set[str] -> RuleEngine(allowlist=...)
                                                   -> SourceContextResolver (STEP 2B)

*** ไม่ตัดสิน risk / ไม่ block *** — แค่ supply data ให้ชั้นที่ตัดสิน
    RULE-003 (Rule Engine) = ยกเว้นการ auto-block
    factor C (Risk Model)  = allowlisted -> 0

รูปแบบไฟล์:
    allowlist:
      - "192.0.2.10"        # หนึ่ง IP ต่อรายการ (IPv4 หรือ IPv6)
      - "2001:db8::1"
    allowlist: []           # ว่าง = ไม่มี source ใดถูกยกเว้น

Policy (strict — safety config ต้องพังให้รู้ทันที):
    - invalid IP -> raise AllowlistError (ไม่ข้ามเงียบ ไม่งั้น IP ที่ตั้งใจ allowlist
      แต่สะกดผิด จะหลุดไปโดน auto-block)
    - ไฟล์ไม่มีอยู่ / YAML เสีย / โครงสร้างผิด -> raise AllowlistError
"""
import ipaddress
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ALLOWLIST_PATH = ROOT / "config" / "allowlist.yaml"


class AllowlistError(Exception):
    """ไฟล์ allowlist หาย/ผิด format หรือมี IP ที่ไม่ถูกต้อง"""


def load_allowlist(path=DEFAULT_ALLOWLIST_PATH) -> set:
    """อ่าน allowlist.yaml -> set ของ canonical IP string
    raise AllowlistError ถ้าไฟล์หาย YAML เสีย หรือมี IP เสีย"""
    p = Path(path)
    if not p.is_file():
        raise AllowlistError(f"allowlist file not found: {p}")

    try:
        with p.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise AllowlistError(f"allowlist ไม่ใช่ YAML ที่ถูกต้อง ({p}): {exc}") from exc

    # ไฟล์ที่มีแต่ comment -> safe_load คืน None ถือว่า allowlist ว่าง
    if data is None:
        return set()
    if not isinstance(data, dict):
        raise AllowlistError(f"allowlist ต้องเป็น mapping ที่ระดับบนสุด ({p})")

    if "allowlist" not in data:
        raise AllowlistError(f"allowlist ต้องมี key 'allowlist' ({p})")

    entries = data["allowlist"]
    if entries is None:
        return set()
    if not isinstance(entries, list):
        raise AllowlistError(
            f"key 'allowlist' ต้องเป็น list ได้ {type(entries).__name__} ({p})")

    allow = set()
    for index, raw in enumerate(entries):
        if isinstance(raw, bool) or not isinstance(raw, str):
            raise AllowlistError(
                f"allowlist[{index}] ต้องเป็น string ของ IP ได้ {raw!r}")
        value = raw.strip()
        try:
            allow.add(str(ipaddress.ip_address(value)))
        except ValueError:
            raise AllowlistError(f"allowlist[{index}] ไม่ใช่ IP ที่ถูกต้อง: {value!r}")
    return allow
