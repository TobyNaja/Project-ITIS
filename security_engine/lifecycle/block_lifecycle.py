"""
security_engine/lifecycle/block_lifecycle.py

Phase 9.2 — Block Lifecycle Manager

เชื่อม RuleEngine.Decision (Phase 6) + PFSenseEnforcer (Phase 8) + BlockStore (Phase 9.1)
ให้ block มี "ชีวิต" ตามเวลา:  BLOCK → รอ block_duration → UNBLOCK

Responsibility ที่แยกชัด:
    RuleEngine  = ควร block ไหม และนานเท่าไร (decision.block_duration)
    Manager     = จัดการ block ให้มีชีวิตตามเวลานั้น (ชั้นนี้)
    Enforcer    = สั่ง pfSense block/unblock อย่างไร

หลักที่ล็อก:
- block_duration มาจาก decision เท่านั้น ไม่ hard-code 300
- เขียน SQLite เป็น ACTIVE ก็ต่อเมื่อ enforcer.add_block() verified สำเร็จ
  (DB ต้องไม่บอกว่า active ทั้งที่ pfSense ไม่ได้ block จริง)
- ตอน remove: verified=True → UNBLOCKED, verified=False → REMOVE_FAILED (retry ได้)
- Manager ไม่มี infinite loop เอง — Lifecycle Runner (ภายหลัง) เป็นคนเรียก expire_due เป็นระยะ
"""
from datetime import datetime, timedelta, timezone

from security_engine.policy.rule_engine import BLOCK


def _default_clock():
    return datetime.now(timezone.utc)


class BlockLifecycleManager:
    def __init__(self, enforcer, store, clock=_default_clock):
        self.enforcer = enforcer
        self.store = store
        self.clock = clock          # callable -> aware UTC datetime

    # ---------- BLOCK ----------
    def block(self, decision):
        """
        รับ Decision (action=BLOCK) -> add_block ที่ pfSense -> ถ้า verified บันทึก ACTIVE
        คืน EnforcementResult ของ add_block (ให้ผู้เรียกดูผลได้)
        """
        # guard: Manager รับเฉพาะ decision ที่สั่ง BLOCK เท่านั้น
        # MONITOR/ALERT/NO_AUTO_BLOCK ต้องไม่มีทางมาสั่ง add_block ที่ pfSense
        if decision.action != BLOCK:
            raise ValueError(
                "BlockLifecycleManager.block() requires action=BLOCK, "
                f"got {decision.action!r}"
            )

        ip = decision.src_ip
        result = self.enforcer.add_block(ip)

        # เขียน ACTIVE เฉพาะเมื่อ pfSense ยืนยันว่า block จริง
        if result.success:
            now = self.clock()
            expires_at = now + timedelta(seconds=decision.block_duration)
            self.store.add_block(
                src_ip=ip,
                blocked_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
                rule_id=getattr(decision, "rule_id", None),
                reason=getattr(decision, "reason", None),
            )
        return result

    # ---------- EXPIRE ----------
    def _try_remove(self, ip):
        """เรียก enforcer.remove_block แล้วอัปเดต store ตามผล verify"""
        result = self.enforcer.remove_block(ip)
        if result.success:
            self.store.remove_block(ip)            # -> UNBLOCKED
        else:
            self.store.mark_remove_failed(ip)      # -> REMOVE_FAILED (retry รอบหน้า)
        return result

    def expire_due(self, now=None):
        """
        ปลด block ที่หมดอายุ + retry ตัวที่เคย REMOVE_FAILED
        คืน list ของ (ip, EnforcementResult) ที่ดำเนินการรอบนี้
        ผู้เรียก (Runner) เป็นคนเรียกเมธอดนี้เป็นระยะ — Manager ไม่ loop เอง
        """
        if now is None:
            now = self.clock()

        processed = []

        # 1) block ที่ ACTIVE และหมดอายุแล้ว
        for blk in self.store.get_expired_blocks(now):
            processed.append((blk["src_ip"], self._try_remove(blk["src_ip"])))

        # 2) retry ตัวที่เคยปลดไม่สำเร็จ (ไม่ว่าเวลาไหน — มันควรถูกปลดไปแล้ว)
        for blk in self.store.get_blocks_by_status("REMOVE_FAILED"):
            processed.append((blk["src_ip"], self._try_remove(blk["src_ip"])))

        return processed

    # ---------- RECONCILE (startup) ----------
    def reconcile(self, now=None):
        """
        ตอน SEC01/process เริ่มใหม่: อ่าน state จาก SQLite (ไม่ใช่ memory)
        - block ที่หมดอายุแล้วระหว่างที่ดับ -> ปลดทันที
        - REMOVE_FAILED ที่ค้าง -> retry
        - block ที่ยังไม่หมดอายุ -> คง ACTIVE ไว้
        คืน list เดียวกับ expire_due
        """
        return self.expire_due(now)