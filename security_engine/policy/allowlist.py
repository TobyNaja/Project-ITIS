"""
security_engine/policy/allowlist.py — Phase 10 Allowlist Loader

หน้าที่เดียว: อ่านไฟล์ allowlist -> คืน set ของ IP (canonical string)
    allowlist.txt -> load_allowlist() -> set[str] -> RuleEngine(allowlist=...)

*** ไม่ตัดสิน risk / ไม่ block ไม่ block *** — แค่ supply data ให้ RuleEngine
ซึ่งเป็นคนตัดสิน NO_AUTO_BLOCK (RULE-003) เอง

รูปแบบไฟล์:
    - หนึ่ง IP ต่อบรรทัด (IPv4 หรือ IPv6)
    - บรรทัดว่างถูกข้าม
    - บรรทัดขึ้นต้น # เป็น comment ถูกข้าม (รวม inline comment: "1.2.3.4  # gateway")
    - whitespace หัวท้ายถูกตัด
    - duplicate ถูก dedupe (เป็น set)

Policy (strict — safety config ต้องพังให้รู้ทันที):
    - invalid IP -> raise AllowlistError (ไม่ข้ามเงียบ ไม่งั้น IP ที่ตั้งใจ allowlist
      แต่สะกดผิด จะหลุดไปโดน auto-block)
    - ไฟล์ไม่มีอยู่ -> raise AllowlistError
"""
import ipaddress
from pathlib import Path


class AllowlistError(Exception):
    """ไฟล์ allowlist หาย หรือมีบรรทัด IP ที่ไม่ถูกต้อง"""


def load_allowlist(path) -> set:
    """อ่านไฟล์ allowlist -> set ของ canonical IP string
    raise AllowlistError ถ้าไฟล์หายหรือมี IP เสีย"""
    p = Path(path)
    if not p.exists():
        raise AllowlistError(f"allowlist file not found: {p}")

    allow = set()
    with p.open(encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # ตัด inline comment: "1.2.3.4  # gateway" -> "1.2.3.4"
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                ip = str(ipaddress.ip_address(line))
            except ValueError:
                raise AllowlistError(
                    f"invalid IP on line {lineno}: {line!r}"
                )
            allow.add(ip)
    return allow