"""
security_engine/policy/source_context.py — Source Context Resolver (Blueprint §3.5 factor C)

หน้าที่เดียว: ตอบว่า source IP หนึ่ง ๆ อยู่ในสถานะไหน
    src_ip -> resolve() -> SourceContext(allowlisted, known_asset)

*** ไม่คำนวณคะแนน *** — Risk Model เป็นคนแปลง SourceContext เป็น factor C
    allowlisted -> 0 | known lab asset -> 30 | unknown/external -> 80

STEP 2B: runner ใช้ load_source_context() — อ่าน allowlist.yaml + assets.yaml
        แล้วคืน allowlist ชุดเดียวกับที่ต้องส่งให้ RuleEngine (RULE-003 <-> C=0
        ต้องมาจาก source เดียวกัน ไม่งั้น decision กับ risk evidence จะขัดกัน)
"""
from typing import Protocol

from security_engine.models import SourceContext
from security_engine.policy.allowlist import DEFAULT_ALLOWLIST_PATH, load_allowlist
from security_engine.policy.assets import DEFAULT_ASSETS_PATH, load_assets


class SourceContextResolver(Protocol):
    """interface ที่ Risk pipeline ต้องการ — implementation ไหนก็ได้"""

    def resolve(self, src_ip: str) -> SourceContext:
        ...


class StaticSourceContextResolver:
    """resolver จาก set ที่ inject เข้ามา (ไม่อ่านไฟล์)

    allowlist มาก่อน known_asset เสมอ — แต่การ "มาก่อน" จริง ๆ ตัดสินที่ Risk Model
    ชั้นนี้แค่รายงานสถานะทั้งสองตามความจริง
    """

    def __init__(self, allowlist=None, known_assets=None):
        self.allowlist = set(allowlist or ())
        self.known_assets = set(known_assets or ())

    def resolve(self, src_ip: str) -> SourceContext:
        return SourceContext(
            allowlisted=src_ip in self.allowlist,
            known_asset=src_ip in self.known_assets,
        )


class UnknownSourceContextResolver:
    """default ระหว่างที่ยังไม่มี config/assets.yaml — ถือว่าทุก source เป็น
    unknown/external (C=80 ซึ่งเป็นค่าที่ conservative ที่สุด ไม่ลดความเสี่ยงให้ใคร)

    *** ห้ามใช้เป็น resolver ถาวร *** — ต้องแทนด้วยตัวที่อ่าน asset list จริงใน STEP 2B
    """

    def resolve(self, src_ip: str) -> SourceContext:
        return SourceContext(allowlisted=False, known_asset=False)


def load_source_context(allowlist_path=DEFAULT_ALLOWLIST_PATH,
                        assets_path=DEFAULT_ASSETS_PATH):
    """อ่าน config -> (allowlist, resolver)

    caller ต้องส่ง allowlist ที่คืนไปให้ RuleEngine ตัวเดียวกับ pipeline นี้
    raise AllowlistError / AssetsError ถ้าไฟล์ใดหายหรือเสีย (ไม่ fallback เงียบ)
    """
    allowlist = load_allowlist(allowlist_path)
    resolver = StaticSourceContextResolver(
        allowlist=allowlist, known_assets=load_assets(assets_path))
    return allowlist, resolver
