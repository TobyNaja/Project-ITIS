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
- FR-11 duplicate handling: source ที่มี block สถานะ ACTIVE อยู่แล้ว จะไม่ถูก block ซ้ำ
  ไม่เรียก enforcer ซ้ำ ไม่แตะ DB และ **ไม่เลื่อน expires_at** (block ต้องหมดอายุ
  ตามเวลาที่ตั้งไว้ครั้งแรก ไม่งั้น M9/T6 วัดผิด) — คืน DuplicateBlockResult พร้อม log
- STEP 6C: source ที่ค้างสถานะ REMOVE_FAILED จะไม่ถูก block ใหม่ทับสถานะ
  (INSERT OR REPLACE จะเขียนกลับเป็น ACTIVE ทำให้ retry หาไม่เจอ = state machine เพี้ยน)
  ต้องปล่อยให้ retry ปลดของเดิมให้สำเร็จก่อน — คืน RemovalPendingResult
- retry การปลด block ไม่วนไม่รู้จบ: ล้มครบ max_remove_attempts -> หยุด retry อัตโนมัติ
  + log CRITICAL (ALERT ตาม NFR-06) โดย **คงสถานะ REMOVE_FAILED ไว้** ไม่เขียน EXPIRED ปลอม
- block_duration มาจาก decision เท่านั้น ไม่ hard-code 300
- เขียน SQLite เป็น ACTIVE ก็ต่อเมื่อ enforcer.add_block() verified สำเร็จ
  (DB ต้องไม่บอกว่า active ทั้งที่ pfSense ไม่ได้ block จริง)
- ตอน remove: verified=True → EXPIRED, verified=False → REMOVE_FAILED (retry ได้)
- Manager ไม่มี infinite loop เอง — Lifecycle Runner (ภายหลัง) เป็นคนเรียก expire_due เป็นระยะ
- STEP 6D: การปลด block ถูกบันทึกเป็น actions.action = UNBLOCK (§3.4) ผ่าน repository
  ที่ inject เข้ามา (optional) โดยผูกกับ decision เดิมที่สั่ง BLOCK
  *** active_blocks.action_id ยังชี้ BLOCK action เดิมเสมอ *** — ไม่เขียนทับด้วย
  UNBLOCK เพราะ schema ให้ความหมายว่าเป็น action ที่ทำให้ block นี้เกิดขึ้น
"""
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from security_engine.policy.rule_engine import BLOCK
from security_engine.storage.schema import STATUS_ACTIVE, STATUS_REMOVE_FAILED

log = logging.getLogger(__name__)

STATUS_DUPLICATE = "DUPLICATE"
STATUS_REMOVAL_PENDING = "REMOVAL_PENDING"
DEFAULT_MAX_REMOVE_ATTEMPTS = 3


@dataclass(frozen=True)
class DuplicateBlockResult:
    """ผลของการ block ที่ถูกระงับเพราะ IP มี block ACTIVE อยู่แล้ว (FR-11)

    contract เดียวกับ EnforcementResult เพื่อให้ผู้เรียกจัดการได้เหมือนกัน แต่:
      success=False  -> ไม่ใช่ enforcement ที่สำเร็จ (ไม่มีคำสั่งถูกส่งไป pfSense)
      duplicate=True -> ไม่ใช่ความล้มเหลวเช่นกัน — ของเดิมยัง block อยู่ตามปกติ
    """
    ip: str
    action: str = "duplicate"
    command_ok: bool = False
    verified: bool = False
    status: str = STATUS_DUPLICATE
    duplicate: bool = True
    suppressed: bool = True        # ไม่มีคำสั่งถูกส่ง -> ไม่มี action ให้ audit

    @property
    def success(self) -> bool:
        return False

    def __str__(self):
        return f"[ENFORCE] duplicate {self.ip} — มี ACTIVE block อยู่แล้ว ไม่สั่งซ้ำ"


@dataclass(frozen=True)
class RemovalPendingResult:
    """ผลของการ block ที่ถูกระงับเพราะ IP ค้างสถานะ REMOVE_FAILED (STEP 6C)

    ของเดิม "ควรถูกปลดแล้วแต่ปลดไม่สำเร็จ" — firewall อาจยัง block อยู่จริง
    ถ้า block ทับตรง ๆ สถานะ REMOVE_FAILED จะหายไป แล้ว retry จะหาไม่เจอ
    ต้องปล่อยให้ retry ปลดของเดิมให้จบก่อน แล้วค่อย block รอบใหม่
    """
    ip: str
    action: str = "removal_pending"
    command_ok: bool = False
    verified: bool = False
    status: str = STATUS_REMOVAL_PENDING
    duplicate: bool = False
    suppressed: bool = True

    @property
    def success(self) -> bool:
        return False

    def __str__(self):
        return (f"[ENFORCE] removal pending {self.ip} — ค้างสถานะ REMOVE_FAILED "
                "ต้องปลดของเดิมให้สำเร็จก่อน")


def _default_clock():
    return datetime.now(timezone.utc)


class BlockLifecycleManager:
    def __init__(self, enforcer, store, clock=_default_clock,
                 max_remove_attempts=DEFAULT_MAX_REMOVE_ATTEMPTS, repository=None):
        self.enforcer = enforcer
        self.store = store
        # repository: AuditRepository optional — None = ไม่บันทึก UNBLOCK action
        # (unit test ที่สนใจแค่ state machine ไม่ต้องมี DB audit)
        self.repository = repository
        self.clock = clock          # callable -> aware UTC datetime
        # เพดาน retry ของการ "ปลด" block — กัน retry วนไม่รู้จบ
        self.max_remove_attempts = max_remove_attempts
        # นับ attempt ต่อ IP ในหน่วยความจำ (schema §3.4 ไม่มีคอลัมน์เก็บ attempt
        # ของ unblock — การเพิ่มคอลัมน์เป็นการแก้ schema ซึ่งอยู่นอก STEP 6C)
        self._remove_attempts = {}

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
        existing = self.store.get_block(ip)

        # ---- FR-11: มี block ACTIVE อยู่แล้ว -> ไม่ทำอะไรทั้งสิ้น ----
        # ไม่เรียก enforcer (ไม่ยิง pfSense ซ้ำ) และไม่แตะ store
        # (INSERT OR REPLACE จะเขียนทับ expires_at = เลื่อนเวลาหมดอายุเงียบ ๆ)
        if existing is not None and existing["status"] == STATUS_ACTIVE:
            log.info("duplicate pattern ระหว่างที่ %s ถูก block อยู่ "
                     "(expires_at=%s) — ไม่ block ซ้ำ", ip, existing["expires_at"])
            return DuplicateBlockResult(ip=ip)

        # ---- STEP 6C: ค้าง REMOVE_FAILED -> ห้าม block ทับสถานะ ----
        if existing is not None and existing["status"] == STATUS_REMOVE_FAILED:
            log.warning("%s ค้างสถานะ REMOVE_FAILED (attempts=%s) — ไม่ block ใหม่ทับ "
                        "ต้องปลดของเดิมให้สำเร็จก่อน", ip, self.removal_attempts(ip))
            return RemovalPendingResult(ip=ip)

        result = self.enforcer.add_block(ip)

        # เขียน ACTIVE เฉพาะเมื่อ pfSense ยืนยันว่า block จริง
        if result.success:
            now = self.clock()
            expires_at = now + timedelta(seconds=decision.block_duration)
            # rule_id/reason ไม่เก็บซ้ำที่นี่ (STEP 5D) — canonical อยู่ที่ decisions
            # ซึ่งย้อนถึงได้ผ่าน active_blocks.action_id -> actions.decision_id
            self.store.add_block(
                src_ip=ip,
                blocked_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
            )
        return result

    # ---------- EXPIRE ----------
    def removal_attempts(self, ip) -> int:
        """จำนวนครั้งที่พยายามปลด block นี้แล้วไม่สำเร็จ (0 = ยังไม่เคยล้ม)"""
        return self._remove_attempts.get(ip, 0)

    def is_removal_exhausted(self, ip) -> bool:
        """ล้มครบเพดานแล้วหรือยัง — ตัวที่ exhausted จะไม่ถูก retry อัตโนมัติอีก"""
        return self.removal_attempts(ip) >= self.max_remove_attempts

    def _try_remove(self, ip):
        """เรียก enforcer.remove_block แล้วอัปเดต store ตามผล verify

        ล้ม -> REMOVE_FAILED + log ERROR ทันที (NFR-06: ค้าง block อันตรายกว่า)
        ล้มครบเพดาน -> log CRITICAL แล้วหยุด retry อัตโนมัติ (สถานะยังคง REMOVE_FAILED)
        """
        # อ่าน action_id ของ BLOCK เดิมไว้ก่อน (ใช้ผูก UNBLOCK เข้ากับ decision เดียวกัน)
        block_action_id = self._block_action_id(ip)

        result = self.enforcer.remove_block(ip)
        if result.success:
            self.store.remove_block(ip)            # -> EXPIRED
            self._remove_attempts.pop(ip, None)
            self._audit_unblock(block_action_id, result)
            return result

        attempts = self.removal_attempts(ip) + 1
        self._remove_attempts[ip] = attempts
        self.store.mark_remove_failed(ip)          # -> REMOVE_FAILED (retry รอบหน้า)
        log.error("ปลด block %s ไม่สำเร็จ (attempt %s/%s) — firewall อาจยัง block อยู่",
                  ip, attempts, self.max_remove_attempts)
        if attempts >= self.max_remove_attempts:
            log.critical("ปลด block %s ล้มครบ %s ครั้ง — หยุด retry อัตโนมัติ "
                         "สถานะคง REMOVE_FAILED ต้องให้ผู้ดูแลเข้ามาจัดการ",
                         ip, self.max_remove_attempts)
        self._audit_unblock(block_action_id, result)
        return result

    # ---------- AUDIT (STEP 6D) ----------
    def _block_action_id(self, ip):
        blk = self.store.get_block(ip)
        return blk.get("action_id") if blk else None

    def _audit_unblock(self, block_action_id, result):
        """บันทึกผลการปลด block เป็น actions.action = UNBLOCK (§3.4 / M9)

        ผูกเข้ากับ decision เดิมที่สั่ง BLOCK ผ่าน actions.decision_id
        (ไล่จาก active_blocks.action_id -> actions.decision_id) จึงไม่ต้องเพิ่ม
        คอลัมน์ใหม่ใน schema — และไม่แตะ active_blocks.action_id ที่ยังหมายถึง BLOCK

        audit ล้ม != enforcement ล้ม: สถานะ block ถูกอัปเดตไปแล้วตามผลจริง
        AuditPersistenceError จะทะลุขึ้นไปให้ผู้เรียกเห็น (runner log ผ่าน on_error)
        """
        if self.repository is None:
            return
        decision_id = None
        if block_action_id is not None:
            block_action = self.repository.get_action(block_action_id)
            if block_action is not None:
                decision_id = block_action["decision_id"]
        self.repository.save_enforcement_action(decision_id, result)

    def expire_due(self, now=None):
        """
        ปลด block ที่หมดอายุ + retry ตัวที่เคย REMOVE_FAILED
        คืน list ของ (ip, EnforcementResult) ที่ดำเนินการรอบนี้
        ผู้เรียก (Runner) เป็นคนเรียกเมธอดนี้เป็นระยะ — Manager ไม่ loop เอง
        """
        if now is None:
            now = self.clock()

        processed = []
        handled = set()

        # 1) block ที่ ACTIVE และหมดอายุแล้ว
        for blk in self.store.get_expired_blocks(now):
            ip = blk["src_ip"]
            handled.add(ip)
            processed.append((ip, self._try_remove(ip)))

        # 2) retry ตัวที่เคยปลดไม่สำเร็จ (ไม่ว่าเวลาไหน — มันควรถูกปลดไปแล้ว)
        #    - ข้ามตัวที่เพิ่งพยายามปลดไปในรอบนี้ (ข้อ 1 อาจเพิ่ง mark REMOVE_FAILED)
        #      ไม่งั้น tick เดียวจะยิง pfSense สองครั้งและกิน attempt ซ้อน
        #    - ข้ามตัวที่ล้มครบเพดานแล้ว เพื่อไม่ให้ retry วนไม่รู้จบ
        for blk in self.store.get_blocks_by_status(STATUS_REMOVE_FAILED):
            ip = blk["src_ip"]
            if ip in handled or self.is_removal_exhausted(ip):
                continue
            processed.append((ip, self._try_remove(ip)))

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
