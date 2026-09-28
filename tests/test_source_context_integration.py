"""
tests/test_source_context_integration.py — STEP 2B: factor C จาก config จริงเข้า pipeline

พิสูจน์:
  1. load_source_context(): allowlist.yaml + assets.yaml -> resolver (unknown/allowlisted/known)
  2. risk ตาม §3.5: unknown C=80 -> 79.5 (golden) | allowlisted C=0 -> 67.5 (ไม่ใช่ 0)
  3. runner ทั้งสองตัว (run_experiment / run_phase4) ส่ง resolver เข้า SecurityPipeline
     และ RuleEngine กับ resolver ได้ allowlist ชุดเดียวกัน
  4. end-to-end: allowlisted -> C=0, risk 67.5, RULE-003 NO_AUTO_BLOCK

ไฟล์ config ทั้งหมดเป็น tmp — ไม่แตะ config/ ของ repo และไม่ต่อ pfSense
"""
from datetime import datetime, timedelta, timezone

import pytest

import run_experiment as rx
import run_phase4
from security_engine.models import CorrelationPattern, SourceContext
from security_engine.policy.source_context import (
    StaticSourceContextResolver, load_source_context,
)
from security_engine.scoring.risk import calculate

P6_SRC = "192.168.2.10"        # Kali — allowlist ชั่วคราวตาม P6
UNKNOWN_SRC = "198.51.100.77"  # TEST-NET — ไม่อยู่ทั้ง allowlist และ assets
ASSET_SRC = "192.0.2.20"       # TEST-NET — ใช้เฉพาะ test ของ C=30 (lab จริงไม่มี asset)

T0 = datetime(2026, 9, 23, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def config_files(tmp_path):
    allow = tmp_path / "allowlist.yaml"
    allow.write_text(f'allowlist:\n  - "{P6_SRC}"\n', encoding="utf-8")
    assets = tmp_path / "assets.yaml"
    assets.write_text(f'assets:\n  - "{ASSET_SRC}"\n', encoding="utf-8")
    return str(allow), str(assets)


def golden_pattern(src):
    """5 HIGH ใน 4.2s -> S=75 F=70 T=100 (§3.5 golden case)"""
    return CorrelationPattern(src_ip=src, window_start=T0,
                              window_end=T0 + timedelta(seconds=4.2),
                              event_count=5, max_severity=1)


# ---- 1. resolver จาก config ----
def test_unknown_source_context(config_files):
    _, resolver = load_source_context(*config_files)
    assert resolver.resolve(UNKNOWN_SRC) == SourceContext(allowlisted=False,
                                                          known_asset=False)


def test_allowlisted_source_context(config_files):
    allowlist, resolver = load_source_context(*config_files)
    assert allowlist == {P6_SRC}
    assert resolver.resolve(P6_SRC).allowlisted is True


def test_known_asset_context(config_files):
    """model รองรับ C=30 — lab จริงไม่มี asset ที่ยืนยันได้ จึงใช้ tmp file"""
    _, resolver = load_source_context(*config_files)
    ctx = resolver.resolve(ASSET_SRC)
    assert ctx == SourceContext(allowlisted=False, known_asset=True)
    assert calculate(golden_pattern(ASSET_SRC), ctx).context_score == 30


def test_repo_config_resolves_every_source_as_unknown():
    """config ของ repo: allowlist ว่าง + assets ว่าง -> ทุก source C=80"""
    allowlist, resolver = load_source_context()
    assert allowlist == set()
    for ip in (P6_SRC, UNKNOWN_SRC, "192.168.1.10", "192.168.1.11"):
        assert resolver.resolve(ip) == SourceContext()


def test_missing_assets_file_fails_loudly(tmp_path, config_files):
    from security_engine.policy.assets import AssetsError
    with pytest.raises(AssetsError):
        load_source_context(config_files[0], tmp_path / "nope.yaml")


# ---- 2. risk ตาม §3.5 ----
def test_golden_risk_case(config_files):
    _, resolver = load_source_context(*config_files)
    risk = calculate(golden_pattern(UNKNOWN_SRC), resolver.resolve(UNKNOWN_SRC))
    assert risk.context_score == 80
    assert risk.risk_score == 79.5


def test_allowlisted_risk_not_zero(config_files):
    """allowlist ลด factor C เป็น 0 เท่านั้น — risk score ไม่เป็น 0 ทั้งก้อน"""
    _, resolver = load_source_context(*config_files)
    risk = calculate(golden_pattern(P6_SRC), resolver.resolve(P6_SRC))
    assert risk.context_score == 0
    assert risk.risk_score == 67.5


# ---- 3. runner wiring ----
class _Result:
    """result ครบ field ที่ audit chain ของ run_phase4 ต้องใช้"""
    def __init__(self, action, ip):
        self.action = action
        self.ip = ip
        self.command_ok = self.verified = self.success = True
        self.status = "ENFORCED"


class FakeEnforcer:
    """ไม่ต่อ pfSense — test นี้สนใจ factor C กับ decision ไม่ใช่ enforcement"""
    def add_block(self, ip): return _Result("add", ip)
    def remove_block(self, ip): return _Result("remove", ip)
    def is_blocked(self, ip): return False
    def get_blocked_ips(self): return set()


def _phase4_pipeline(tmp_path, config_files):
    allow, assets = config_files
    pipeline, _, _ = run_phase4.build_pipeline(
        allowlist_path=allow, assets_path=assets,
        db_path=str(tmp_path / "phase4.db"), enforcer=FakeEnforcer())
    return pipeline


def _experiment_pipeline(tmp_path, config_files):
    pipeline, _, _ = rx.build("logic", None, str(tmp_path / "exp.db"),
                              load_source_context(*config_files))
    return pipeline


RUNNERS = [_phase4_pipeline, _experiment_pipeline]


@pytest.mark.parametrize("make", RUNNERS, ids=["run_phase4", "run_experiment"])
def test_runner_passes_resolver(tmp_path, config_files, make):
    pipeline = make(tmp_path, config_files)
    resolver = pipeline.source_context_resolver
    assert isinstance(resolver, StaticSourceContextResolver)
    # RULE-003 กับ factor C ต้องมาจาก allowlist ชุดเดียวกัน
    assert pipeline.rule_engine.allowlist == resolver.allowlist == {P6_SRC}
    assert resolver.known_assets == {ASSET_SRC}


def test_both_runners_use_same_context(tmp_path, config_files):
    a = _phase4_pipeline(tmp_path, config_files).source_context_resolver
    b = _experiment_pipeline(tmp_path, config_files).source_context_resolver
    for ip in (P6_SRC, UNKNOWN_SRC, ASSET_SRC):
        assert a.resolve(ip) == b.resolve(ip)


# ---- 4. end-to-end ผ่าน pipeline จริง (จับ RiskAssessment ที่ pipeline คำนวณ) ----
@pytest.fixture
def captured_risk(monkeypatch):
    import security_engine.pipeline as pipeline_module
    seen = []

    def spy(pattern, source_context, **kwargs):
        risk = calculate(pattern, source_context, **kwargs)
        seen.append(risk)
        return risk

    monkeypatch.setattr(pipeline_module, "calculate", spy)
    return seen


def _feed(pipeline, events):
    trace = None
    for ev in events:
        trace = pipeline.process(ev)
    return trace


@pytest.mark.parametrize("make", RUNNERS, ids=["run_phase4", "run_experiment"])
def test_allowlisted_pattern_end_to_end(tmp_path, config_files, captured_risk, make):
    pipeline = make(tmp_path, config_files)
    events, _ = rx.scenario_events("T5", {P6_SRC})
    trace = _feed(pipeline, events)

    (risk,) = captured_risk
    assert risk.context_score == 0
    assert risk.risk_score == 67.5
    assert trace["decision"] == "NO_AUTO_BLOCK"


@pytest.mark.parametrize("make", RUNNERS, ids=["run_phase4", "run_experiment"])
def test_unknown_pattern_end_to_end(tmp_path, config_files, captured_risk, make):
    pipeline = make(tmp_path, config_files)
    events, _ = rx.scenario_events("T4")
    trace = _feed(pipeline, events)

    (risk,) = captured_risk
    assert risk.context_score == 80
    assert risk.risk_score == 79.5
    assert trace["decision"] == "BLOCK"


def test_allowlisted_decision_uses_rule_003(config_files):
    from security_engine.policy.rule_engine import RuleEngine, NO_AUTO_BLOCK
    from security_engine.policy.rules_config import load_rules

    allowlist, resolver = load_source_context(*config_files)
    pattern = golden_pattern(P6_SRC)
    risk = calculate(pattern, resolver.resolve(P6_SRC))
    decision = RuleEngine(load_rules(), allowlist=allowlist).decide(risk, pattern)
    assert decision.action == NO_AUTO_BLOCK
    assert decision.rule_id == "RULE-003"
    assert risk.risk_score == 67.5
