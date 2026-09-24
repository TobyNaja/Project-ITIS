"""
security_engine/experiment/timestamp_sink.py — FR-15 ใน runtime engine (run_phase4)

    run_phase4 --test-id T4 --run-id T4-R03
        -> ExperimentTimestampSink(repository, "T4", "T4-R03")
        -> SecurityPipeline(trace_sink=sink) -> _emit(trace) -> sink(trace)
        -> experiment_timestamps (1 แถวต่อ trace ที่ correlation match)

หลักที่ล็อก (STEP 11 protocol amendment):
- identity (test_id + run_id) ผูกกับ sink ตลอดอายุ process — ไม่มี state ภายนอกที่แก้ได้
- run_id มีรูปเดียว (canonical) `<test_id>-R<NN>` เช่น T4-R03 — ค่าเดียวกันทั้ง DB notes
  และ CSV (generator --run 3 -> --run-id T4-R03) ห้ามมีทั้ง "3" และ "T4-R03" ปนใน DB
- ค่าเวลา **คัดลอกจาก trace เดียวกับที่ pipeline ใช้ตัดสินใจ** ไม่สร้างเวลาใหม่
  และไม่ประกอบย้อนหลังจากตารางอื่น
- correlation ไม่ match (เช่น T2/T10) -> ไม่มีแถว: pipeline หยุดก่อนถึง decision stage
  จึงไม่มี t_decision ให้บันทึก (หลักฐานคือ security_events + ไม่มี decisions)
- block ถูกระงับ (duplicate / REMOVE_FAILED) -> t_block_cmd = NULL เพราะไม่มีคำสั่ง
  ถูกส่งไป pfSense จริง (trace ตั้ง t_block_cmd ก่อนเรียก lifecycle.block())
- enforcement verify ล้ม -> t_block_verified = NULL (pipeline ไม่ตั้งค่าให้อยู่แล้ว)
- enforcement โยน exception ก่อน _emit() -> sink ไม่ถูกเรียก -> ไม่มีแถว (ข้อจำกัดที่ระบุ
  ในรายงาน — ไม่แก้ pipeline เพื่อสร้างแถว)
- บันทึกไม่สำเร็จ -> log ERROR แล้วไปต่อ (NFR-06: audit ล้ม ≠ engine ล้ม)
"""
import logging
import re

from security_engine.storage.repository import AuditPersistenceError

log = logging.getLogger(__name__)

VALID_TEST_IDS = tuple(f"T{n}" for n in range(1, 12))   # Blueprint §14.4 canonical
_RUN_ID_PATTERN = re.compile(r"(T(?:[1-9]|1[01]))-R(\d{2})")   # ใช้กับ fullmatch
MODE_INJECTION = "injection"


class ExperimentIdentityError(ValueError):
    """test_id / run_id ไม่ถูกต้อง — ต้องพังก่อน engine เริ่มแตะ pfSense"""


def validate_identity(test_id, run_id):
    """คืน (test_id, run_id) ที่ตรวจแล้ว หรือ raise ExperimentIdentityError"""
    if test_id not in VALID_TEST_IDS:
        raise ExperimentIdentityError(
            f"test_id ต้องเป็นหนึ่งใน {', '.join(VALID_TEST_IDS)} ได้ {test_id!r}")
    match = _RUN_ID_PATTERN.fullmatch(run_id) if isinstance(run_id, str) else None
    if match is None or match.group(1) != test_id:
        raise ExperimentIdentityError(
            f"run_id ต้องเป็นรูป {test_id}-R<NN> (เช่น {test_id}-R03) ได้ {run_id!r}")
    return test_id, run_id


class ExperimentTimestampSink:
    """trace_sink ของ SecurityPipeline — เขียน FR-15 ของ 1 test run"""

    def __init__(self, repository, test_id, run_id, mode=MODE_INJECTION):
        self.repository = repository
        self.test_id, self.run_id = validate_identity(test_id, run_id)
        self.mode = mode

    def __call__(self, trace):
        """คืน id ของแถวที่เขียน หรือ None (ไม่ match / บันทึกไม่สำเร็จ)"""
        if not trace.get("correlation_matched"):
            return None

        suppressed = bool(trace.get("block_suppressed"))
        notes = (f"run={self.run_id}; mode={self.mode}; "
                 f"decision={trace.get('decision')}; suppressed={int(suppressed)}")
        try:
            return self.repository.save_experiment_timestamps(
                self.test_id,
                t_event=trace.get("t_event"),
                t_detection=trace.get("t_detection"),
                t_decision=trace.get("t_decision"),
                t_block_cmd=None if suppressed else trace.get("t_block_cmd"),
                t_block_verified=trace.get("t_block_verified"),
                notes=notes)
        except AuditPersistenceError as exc:
            log.error("บันทึก experiment_timestamps ไม่สำเร็จ (%s run=%s src_ip=%s): %s",
                      self.test_id, self.run_id, trace.get("src_ip"), exc)
            return None
