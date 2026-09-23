"""
security_engine/policy/assets.py — Lab Asset List Loader (Blueprint §3.5 factor C)

หน้าที่เดียว: อ่าน config/assets.yaml -> คืน set ของ IP (canonical string)
    assets.yaml -> load_assets() -> set[str] -> SourceContextResolver(known_assets=...)

*** ไม่ตัดสิน risk / ไม่ block / ไม่เดา role *** — แค่ supply data ให้ Risk Model
    known lab asset -> factor C = 30 (ถ้าไม่ได้ allowlist)

รูปแบบไฟล์ (pattern เดียวกับ allowlist.yaml):
    assets:
      - "192.0.2.20"        # หนึ่ง IP ต่อรายการ (IPv4 หรือ IPv6)
    assets: []              # ว่าง = ไม่มี source ใดเป็น known asset (ทุกตัว C=80)

Policy (strict — เหมือน allowlist):
    - invalid IP -> raise AssetsError (ไม่ข้ามเงียบ ไม่งั้น asset ที่สะกดผิด
      จะได้ C=80 แทน 30 โดยไม่มีใครรู้)
    - ไฟล์ไม่มีอยู่ / YAML เสีย / โครงสร้างผิด -> raise AssetsError
    - IP ซ้ำ -> dedupe (เหมือน allowlist)
"""
import ipaddress
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ASSETS_PATH = ROOT / "config" / "assets.yaml"


class AssetsError(Exception):
    """ไฟล์ asset list หาย/ผิด format หรือมี IP ที่ไม่ถูกต้อง"""


def load_assets(path=DEFAULT_ASSETS_PATH) -> set:
    """อ่าน assets.yaml -> set ของ canonical IP string
    raise AssetsError ถ้าไฟล์หาย YAML เสีย หรือมี IP เสีย"""
    p = Path(path)
    if not p.is_file():
        raise AssetsError(f"assets file not found: {p}")

    try:
        with p.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise AssetsError(f"assets ไม่ใช่ YAML ที่ถูกต้อง ({p}): {exc}") from exc

    # ไฟล์ที่มีแต่ comment -> safe_load คืน None ถือว่า asset list ว่าง
    if data is None:
        return set()
    if not isinstance(data, dict):
        raise AssetsError(f"assets ต้องเป็น mapping ที่ระดับบนสุด ({p})")

    if "assets" not in data:
        raise AssetsError(f"assets ต้องมี key 'assets' ({p})")

    entries = data["assets"]
    if entries is None:
        return set()
    if not isinstance(entries, list):
        raise AssetsError(
            f"key 'assets' ต้องเป็น list ได้ {type(entries).__name__} ({p})")

    assets = set()
    for index, raw in enumerate(entries):
        if isinstance(raw, bool) or not isinstance(raw, str):
            raise AssetsError(
                f"assets[{index}] ต้องเป็น string ของ IP ได้ {raw!r}")
        value = raw.strip()
        try:
            assets.add(str(ipaddress.ip_address(value)))
        except ValueError:
            raise AssetsError(f"assets[{index}] ไม่ใช่ IP ที่ถูกต้อง: {value!r}")
    return assets
