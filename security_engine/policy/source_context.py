"""
security_engine/policy/source_context.py — Source Context Resolver (Blueprint §3.5 factor C)

หน้าที่เดียว: ตอบว่า source IP หนึ่ง ๆ อยู่ในสถานะไหน
    src_ip -> resolve() -> SourceContext(allowlisted, known_asset)

*** ไม่คำนวณคะแนน *** — Risk Model เป็นคนแปลง SourceContext เป็น factor C
    allowlisted -> 0 | known lab asset -> 30 | unknown/external -> 80

STEP 2: มีแค่ static resolver (รับ set เข้ามาตรง ๆ) เพื่อให้ Risk Model ทดสอบได้
        โดยไม่แตะ filesystem — resolver ที่อ่าน config/assets.yaml + allowlist.yaml
        จะทำใน STEP 2B หลังสำรวจ asset จริงของ lab (ดู blueprint-alignment-plan.md)
"""
from typing import Protocol

from security_engine.models import SourceContext


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
