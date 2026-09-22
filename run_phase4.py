"""
run_phase4.py — Phase 11.3 Entry point (thin)

หน้าที่เดียว: ประกอบระบบ แล้วเดิน loop — ไม่มี logic ของ
Correlation/Risk/Rule/Lifecycle อยู่ในนี้ (อยู่ใน module ของแต่ละ phase)

    allowlist -> components -> shared lock -> Pipeline + Runner
    runner.start()
    for event in stream_events(): pipeline.process(event)   [main thread]
    finally: runner.stop()                                    [shutdown สะอาด]

ค่าระบบทั้งหมดมาจาก config/config.yaml (NFR-01) ผ่าน security_engine.settings
ส่วนค่าเฉพาะเครื่องมาจาก environment (NFR-07):
    $env:ITIS_PFSENSE_HOST = "admin@..."          # required
    $env:ITIS_EVE_PATH     = "/var/log/..."       # optional — override eve.path
ไฟล์นี้แยก build_pipeline() ออกจาก main() เพื่อให้ wiring test ประกอบระบบได้
โดยไม่ต้องรัน loop จริง
"""
import logging
import threading

from security_engine.logging_config import configure_from_settings
from security_engine.settings import (          # re-export: ของเดิมที่อ้าง
    ConfigError,                                # run_phase4.ConfigError /
    ENV_EVE_PATH,                               # run_phase4.require_env ยังใช้ได้
    ENV_PFSENSE_HOST,
    load_settings,
    require_env,
)
from security_engine.ingestion.eve_reader import stream_events
from security_engine.correlation.engine import CorrelationEngine
from security_engine.policy.rule_engine import RuleEngine
from security_engine.policy.rules_config import load_rules
from security_engine.policy.allowlist import load_allowlist
from security_engine.enforcement.pfsense_enforcer import PFSenseEnforcer
from security_engine.lifecycle.block_store import BlockStore
from security_engine.lifecycle.block_lifecycle import BlockLifecycleManager
from security_engine.lifecycle.runner import LifecycleRunner
from security_engine.pipeline import SecurityPipeline
from security_engine.storage.repository import AuditRepository

log = logging.getLogger(__name__)

# ---- fallback default ของ build_pipeline (ค่าจริงตอนรันมาจาก config.yaml) ----
# policy config: กฎมาจาก rules.yaml, allowlist มาจาก allowlist.yaml (NFR-01)
ALLOWLIST_PATH = "config/allowlist.yaml"
RULES_PATH = "config/rules.yaml"
DB_PATH = "data/security_engine.db"
MIN_EVENTS = 5
WINDOW_MAX = 10.0

# block-expiry polling interval เป็น implementation-level scheduler parameter
# ไม่ใช่ Blueprint experiment/configuration parameter จึงไม่อยู่ใน config.yaml
# (ห้ามเอา health.check_interval_sec=15 มาใช้แทน — คนละความหมาย)
EXPIRE_INTERVAL_SEC = 1.0


def build_pipeline(*, host=None, allowlist_path=ALLOWLIST_PATH,
                   rules_path=RULES_PATH,
                   db_path=DB_PATH, min_events=MIN_EVENTS,
                   window_max=WINDOW_MAX, expire_interval=EXPIRE_INTERVAL_SEC,
                   enforcer=None, correlator=None, repository=None):
    """
    ประกอบ component ทั้งหมด -> คืน (pipeline, runner, shared_lock)
    เปิดให้ inject enforcer/correlator เพื่อ wiring test (ไม่ต้องต่อ pfSense จริง)

    host=None + ไม่ inject enforcer -> อ่าน ITIS_PFSENSE_HOST จาก environment
    (inject enforcer แล้ว host ไม่ถูกใช้เลย -> test ไม่ต้องตั้ง env)

    repository=None -> สร้าง AuditRepository บน db_path เดียวกับ BlockStore
    (audit chain §3.4 ต้องอยู่ไฟล์เดียวกับ active_blocks ถึงจะ join ได้)
    """
    allowlist = load_allowlist(allowlist_path)
    rules = load_rules(rules_path)

    # window_max ส่งเป็น float ตรงๆ — timedelta(seconds=...) รองรับ float
    # (ห้าม int() เพราะถ้า window_max=2.5 จะถูกตัดเหลือ 2 -> Correlation กับ Risk
    #  ใช้ window คนละค่า)
    correlator = correlator or CorrelationEngine(
        window_seconds=window_max, min_events=min_events)
    # กฎทั้งหมดมาจาก rules.yaml — min_events/window_max เป็นของ CorrelationEngine
    rule_engine = RuleEngine(rules, allowlist=allowlist)
    enforcer = enforcer or PFSenseEnforcer(host or require_env(ENV_PFSENSE_HOST))
    store = BlockStore(db_path)
    repository = repository or AuditRepository(db_path)
    # lifecycle บันทึก UNBLOCK action เอง (STEP 6D) ส่วน BLOCK action บันทึกที่ pipeline
    lifecycle = BlockLifecycleManager(enforcer, store, repository=repository)

    # shared lock: Pipeline (block) + Runner (expire_due) ใช้ตัวเดียวกัน
    shared_lock = threading.Lock()

    pipeline = SecurityPipeline(correlator, rule_engine, lifecycle,
                                lock=shared_lock,
                                min_events=min_events, window_max=window_max,
                                repository=repository)
    runner = LifecycleRunner(
        lifecycle, shared_lock, interval=expire_interval,
        # NFR-02: error ใน expire loop ต้องถูก log ไม่ใช่ตายเงียบ
        on_error=lambda exc: log.error("lifecycle runner error: %s", exc, exc_info=exc))
    return pipeline, runner, shared_lock


def run(pipeline, runner, event_source):
    """
    เดิน loop: reconcile -> start runner -> วน event -> shutdown สะอาดใน finally
    event_source = iterable ของ normalized event (production = stream_events())
    """
    # FR-10 Restart Resilience: อ่าน state จาก SQLite ก่อนเริ่มทำงาน
    #   หมดอายุระหว่างที่ process ดับ -> ปลดทันที
    #   REMOVE_FAILED ที่ค้าง        -> retry
    #   ยังไม่หมดอายุ                -> คง ACTIVE ไว้ (timer เดินต่อด้วย runner)
    # ต้องทำ *ก่อน* runner.start() เพื่อให้ state ถูกต้องตั้งแต่ tick แรก
    runner.lifecycle.reconcile()
    runner.start()
    try:
        for event in event_source:
            # NFR-02: event เดียวพังต้องไม่ล้มทั้ง engine — log แล้วไปตัวถัดไป
            # (สถานะ enforcement ที่เกิดไปแล้วยังคงถูกต้องตามความจริงเสมอ)
            try:
                trace = pipeline.process(event)
            except Exception as exc:                      # noqa: BLE001 — boundary กันล้ม
                log.error("ประมวลผล event ไม่สำเร็จ (src_ip=%s): %s",
                          event.get("src_ip"), exc, exc_info=exc)
                continue
            log.info("event src_ip=%s matched=%s decision=%s",
                     trace["src_ip"], trace["correlation_matched"], trace["decision"])
    finally:
        runner.stop()          # stop_event.set() + join -> thread จบสะอาด


def main():
    # อ่าน+validate config ให้ครบก่อน -> ค่าหาย/เสียจะพังก่อนแตะ pfSense หรือสร้าง db
    settings = load_settings()
    configure_from_settings(settings)       # NFR-03: log ลง logs/engine.log
    log.info("เริ่ม ITIS engine (weight_set=%s, block_duration=%ss)",
             settings.risk.weight_set, settings.block.duration_sec)
    host = settings.pfsense_host()          # environment เท่านั้น (NFR-07)
    eve_path = settings.require_eve_path()  # config.yaml หรือ ITIS_EVE_PATH
    pipeline, runner, _ = build_pipeline(
        host=host,
        db_path=settings.system.db_path,
        min_events=settings.correlation.min_events,
        window_max=float(settings.correlation.window_sec),
    )
    run(pipeline, runner, stream_events(host, eve_path))


if __name__ == "__main__":
    main()