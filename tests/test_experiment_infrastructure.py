"""
tests/test_experiment_infrastructure.py — STEP 10.3/10.4/10.5

พิสูจน์ว่าโครงสร้างการทดลองพร้อมใช้จริงก่อน code freeze:

    generate_test_events.py ──EVE JSON──> eve_reader ──> pipeline ──> decision
                                                              │
    results_template.csv (37 คอลัมน์ §14.5) <─────────────────┘
    docs/test_plan.md (T1–T11 protocol)

หลักที่ต้องกันไว้
- generator สร้าง "input" เท่านั้น — ห้ามมี decision/enforcement/recovery ปนใน output
- input ที่สร้างต้องผ่าน parser จริง (ไม่ใช่ dict ที่ข้ามขั้นตอน ingestion)
- decision ของทุก scenario ต้องมาจาก engine จริง ไม่ใช่ค่าที่ generator ประกาศ
- A1–A4 ต้องไม่ถูกใช้เป็น canonical ID อีก
"""
import csv
import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import generate_test_events as gen                     # noqa: E402

from security_engine.correlation.engine import CorrelationEngine    # noqa: E402
from security_engine.ingestion.eve_reader import iter_events, normalize, parse_line  # noqa: E402
from security_engine.pipeline import SecurityPipeline  # noqa: E402
from security_engine.policy.allowlist import load_allowlist  # noqa: E402
from security_engine.policy.rule_engine import RuleEngine  # noqa: E402
from security_engine.policy.rules_config import load_rules  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "experiments" / "results_template.csv"
TEST_PLAN = ROOT / "docs" / "test_plan.md"

ALL_TESTS = [f"T{n}" for n in range(1, 12)]

# §14.5 Results Template — 37 คอลัมน์ ตามลำดับที่ Blueprint เขียนไว้
EXPECTED_COLUMNS = [
    # identity (5)
    "test_id", "run_id", "scenario", "src_ip", "expected_result",
    # timestamps (7)
    "t_event", "t_detection", "t_decision", "t_block_cmd", "t_block_verified",
    "t_unblock", "t_recovery",
    # latency (5)
    "detection_latency_ms", "decision_latency_ms", "enforcement_latency_ms",
    "end_to_end_latency_ms", "recovery_time_ms",
    # risk (8)
    "event_count", "max_severity", "severity_score", "frequency_score",
    "temporal_score", "context_score", "risk_score", "risk_level",
    # decision (4)
    "weight_set", "rule_id", "decision", "allowlisted",
    # result (3)
    "action_result", "verify_result", "recovery_result",
    # resource (3)
    "cpu_percent", "ram_percent", "pps",
    # evidence (2)
    "notes", "evidence_path",
]


# ================= 10.3 generate_test_events.py =================
def test_all_eleven_test_cases_are_supported():
    assert list(gen.SCENARIOS) == ALL_TESTS


def test_no_legacy_a_labels_in_generator():
    """A1–A4 ปลดระวางแล้ว — ห้ามโผล่เป็น scenario id"""
    assert not [k for k in gen.SCENARIOS if k.startswith("A")]


@pytest.mark.parametrize("test_id", ALL_TESTS)
def test_generated_lines_survive_the_real_parser(test_id):
    """ทุก event ต้องผ่าน parse_line ได้ และ alert ต้อง normalize ผ่าน"""
    for event in gen.generate(test_id):
        line = json.dumps(event)
        parsed = parse_line(line)
        assert parsed is not None
        if parsed["event_type"] == "alert":
            assert normalize(parsed) is not None, "alert ที่สร้างต้องมี field ครบ"


@pytest.mark.parametrize("test_id", ALL_TESTS)
def test_generator_emits_input_only(test_id):
    """ห้ามมี field ของ "ผลลัพธ์" ปนมาใน EVE event"""
    banned = {"decision", "risk_score", "risk_level", "rule_id", "action",
              "verify_result", "recovery_result", "expected_result", "blocked"}
    for event in gen.generate(test_id):
        assert not (banned & set(event)), f"{test_id}: generator ห้ามใส่ผลลัพธ์"
        assert event["event_type"] in ("alert", "stats")


def test_t1_has_no_alerts():
    events = gen.generate("T1")
    assert events, "T1 ต้องมี stats event ให้ health check ใช้"
    assert all(e["event_type"] == "stats" for e in events)


def test_t2_is_a_single_medium_alert():
    events = gen.generate("T2")
    assert len(events) == 1
    assert events[0]["alert"]["severity"] == gen.SEV_MEDIUM


def test_t3_is_five_medium_from_one_source():
    events = gen.generate("T3")
    assert len(events) == 5
    assert {e["alert"]["severity"] for e in events} == {gen.SEV_MEDIUM}
    assert len({e["src_ip"] for e in events}) == 1


def test_t4_is_five_high_from_one_source():
    events = gen.generate("T4")
    assert len(events) == 5
    assert {e["alert"]["severity"] for e in events} == {gen.SEV_HIGH}
    assert events[0]["src_ip"] == gen.DEFAULT_SRC


def test_t5_uses_a_dedicated_allowlist_source():
    events = gen.generate("T5")
    assert {e["src_ip"] for e in events} == {gen.ALLOWLISTED_SRC}
    assert gen.ALLOWLISTED_SRC != gen.DEFAULT_SRC


def test_repo_allowlist_stays_empty_by_default():
    """default policy ของ repo = ไม่ยกเว้นใครเลย

    T5 ต้องให้ผู้ทดลองเพิ่ม IP เองตาม prerequisite P6 — ห้ามใส่ IP ทดลอง
    ลง production config เพื่อให้ test เขียว
    """
    assert load_allowlist(ROOT / "config" / "allowlist.yaml") == set()
    assert "P6" in TEST_PLAN.read_text(encoding="utf-8")


@pytest.mark.parametrize("test_id", ["T4", "T6", "T7", "T11"])
def test_block_pattern_scenarios_share_the_same_input_shape(test_id):
    """T6/T7/T11 ใช้ pattern เดียวกับ T4 — ต่างกันที่ขั้นตอนหลังจากนั้น"""
    events = gen.generate(test_id)
    assert len(events) == 5
    assert {e["alert"]["severity"] for e in events} == {gen.SEV_HIGH}


@pytest.mark.parametrize("variant,count", [("a", 1), ("b", 4)])
def test_t10_variants(variant, count):
    events = gen.generate("T10", variant=variant)
    assert len(events) == count
    assert {e["alert"]["severity"] for e in events} == {gen.SEV_HIGH}


def test_unknown_variant_is_rejected():
    with pytest.raises(ValueError):
        gen.generate("T10", variant="z")
    with pytest.raises(ValueError):
        gen.generate("T4", variant="a")     # T4 ไม่มี variant


def test_unknown_test_id_is_rejected():
    with pytest.raises(ValueError) as exc:
        gen.generate("T99")
    assert "T99" in str(exc.value)


def test_alerts_fit_inside_the_correlation_window():
    """5 event ต้องอยู่ใน 10 วินาที ไม่งั้น T3/T4 จะไม่มีทาง correlate"""
    events = gen.generate("T4")
    times = [datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
             for e in events]
    assert (max(times) - min(times)).total_seconds() < 10


def test_timestamps_are_timezone_aware_utc():
    event = gen.generate("T4")[0]
    parsed = datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    assert parsed.utcoffset().total_seconds() == 0


def test_repetitions_produce_independent_event_sets():
    first = gen.generate("T4", start=datetime(2026, 1, 1, tzinfo=timezone.utc))
    second = gen.generate("T4", start=datetime(2026, 1, 1, 0, 1,
                                               tzinfo=timezone.utc))
    assert first[0]["timestamp"] != second[0]["timestamp"]
    assert len(first) == len(second)


def test_scenarios_needing_manual_action_say_so():
    """T6/T7/T8/T9/T11 มีขั้นตอนที่ generator ทำแทนไม่ได้ — ต้องประกาศไว้"""
    for test_id in ("T6", "T7", "T8", "T9", "T11"):
        assert gen.SCENARIOS[test_id].manual_step, f"{test_id} ต้องระบุขั้นตอนที่ทำเอง"


def test_cli_writes_jsonl_file(tmp_path):
    out = tmp_path / "t3.json"
    rc = gen.main(["--test-id", "T3", "--out", str(out)])
    assert rc == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    assert all(parse_line(line) is not None for line in lines)


def test_cli_runs_as_a_script():
    """เรียกจริงจาก command line ได้ (ไม่ใช่แค่ import)"""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_test_events.py"),
         "--test-id", "T4"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert len(proc.stdout.strip().splitlines()) == 5


def test_cli_list_shows_every_case():
    rc = gen.main(["--list"])
    assert rc == 0


# ---- input ที่สร้าง ต้องทำให้ engine จริงตัดสินได้ตามที่ test plan คาด ----
def decide(test_id, variant=None, allowlist=None):
    """ป้อน EVE ที่ generator สร้าง เข้า ingestion + pipeline จริง คืน decision ของ engine

    allowlist ส่งเข้ามาเหมือนที่ผู้ทดลองตั้งตาม prerequisite P6 (T5 เท่านั้น)
    """
    raw = [json.dumps(e) for e in gen.generate(test_id, variant=variant)]
    events = list(iter_events(iter(raw)))               # ผ่าน FR-02 classification
    pipeline = SecurityPipeline(
        CorrelationEngine(window_seconds=10.0, min_events=5),
        RuleEngine(load_rules(), allowlist=allowlist or set()),
        _NullLifecycle(), lock=threading.Lock(), min_events=5, window_max=10.0)
    trace = None
    for event in events:
        trace = pipeline.process(event)
    return trace


class _NullResult:
    success = True
    command_ok = True
    verified = True
    status = "ENFORCED"
    duplicate = False
    suppressed = False
    action = "add"
    error = None


class _NullLifecycle:
    """ไม่ต่อ pfSense — test นี้สนใจ decision ของ engine ไม่ใช่ enforcement"""

    def __init__(self):
        self.blocked = []

    def block(self, decision):
        self.blocked.append(decision.src_ip)
        return _NullResult()


@pytest.mark.parametrize("test_id,variant,expected", [
    ("T2", None, None),          # alert เดี่ยว -> correlation ไม่ match
    ("T3", None, "ALERT"),
    ("T4", None, "BLOCK"),
    ("T10", "a", None),
    ("T10", "b", None),          # 4 events ยังไม่ถึง min_events=5
])
def test_engine_decides_expected_outcome_for_generated_input(test_id, variant,
                                                             expected):
    """decision มาจาก engine — generator แค่ป้อน input เท่านั้น"""
    trace = decide(test_id, variant)
    assert trace["decision"] == expected


def test_t5_needs_the_allowlist_entry_from_prerequisite_p6():
    """pattern เดียวกับ T4 — ต่างกันแค่ allowlist ที่ผู้ทดลองตั้งไว้"""
    assert decide("T5")["decision"] == "BLOCK"                      # ไม่ได้ตั้ง P6
    trace = decide("T5", allowlist={gen.ALLOWLISTED_SRC})           # ตั้ง P6 แล้ว
    assert trace["decision"] == "NO_AUTO_BLOCK"


def test_t1_produces_no_pipeline_event_at_all():
    """stats ไม่เข้า correlation (FR-02) -> ไม่มี trace"""
    assert decide("T1") is None


def test_t1_stats_reach_the_stats_callback():
    raw = [json.dumps(e) for e in gen.generate("T1")]
    seen = []
    alerts = list(iter_events(iter(raw), on_stats=seen.append))
    assert alerts == []
    assert len(seen) == 3, "stats ต้องถูกส่งเข้า on_stats สำหรับ health check"


# ================= 10.4 results_template.csv =================
def test_template_exists_and_has_header_only():
    assert TEMPLATE.is_file()
    rows = list(csv.reader(TEMPLATE.open(encoding="utf-8")))
    assert len(rows) == 1, "template ต้องมีแต่หัวตาราง ไม่มีข้อมูลตัวอย่าง"


def test_template_has_exactly_the_37_blueprint_columns():
    header = next(csv.reader(TEMPLATE.open(encoding="utf-8")))
    assert len(header) == 37
    assert header == EXPECTED_COLUMNS


def test_template_column_groups_add_up():
    """identity 5 + timestamps 7 + latency 5 + risk 8 + decision 4 +
       result 3 + resource 3 + evidence 2 = 37"""
    assert 5 + 7 + 5 + 8 + 4 + 3 + 3 + 2 == 37


def test_template_covers_every_metric_input():
    header = set(next(csv.reader(TEMPLATE.open(encoding="utf-8"))))
    # M1–M4 ต้องคำนวณได้จาก timestamp ที่มีในตาราง
    assert {"t_event", "t_detection", "t_decision", "t_block_verified"} <= header
    # M8/M9/M10
    assert {"allowlisted", "t_unblock", "recovery_result", "t_recovery"} <= header
    # T11 factor breakdown
    assert {"severity_score", "frequency_score", "temporal_score",
            "context_score", "weight_set"} <= header


def test_template_is_readable_by_dictwriter(tmp_path):
    """กรอกได้จริงโดยไม่ต้องแก้โครงสร้างกลางการทดลอง"""
    header = next(csv.reader(TEMPLATE.open(encoding="utf-8")))
    out = tmp_path / "filled.csv"
    with out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()
        writer.writerow({"test_id": "T4", "run_id": "T4-R01", "decision": "BLOCK"})
    row = next(csv.DictReader(out.open(encoding="utf-8")))
    assert row["run_id"] == "T4-R01"
    assert row["cpu_percent"] == "", "resource metrics เว้นว่างไว้จนกว่าจะมีค่าจริง"


# ================= 10.5 docs/test_plan.md =================
@pytest.fixture(scope="module")
def plan_text():
    return TEST_PLAN.read_text(encoding="utf-8")


def test_test_plan_exists(plan_text):
    assert len(plan_text) > 1000


@pytest.mark.parametrize("test_id", ALL_TESTS)
def test_every_test_case_is_documented(plan_text, test_id):
    assert f"### {test_id} —" in plan_text


@pytest.mark.parametrize("metric", [f"M{n}" for n in range(1, 11)])
def test_every_metric_is_mapped(plan_text, metric):
    assert metric in plan_text


def test_clock_sync_prerequisite_is_stated(plan_text):
    """M1 คร่อม clock domain — ต้องประกาศ NTP/UTC เป็นเงื่อนไขก่อนวัด"""
    assert "NTP" in plan_text
    assert "clock domain" in plan_text


def test_legacy_labels_appear_only_as_a_note(plan_text):
    """A1–A4 ต้องไม่ถูกใช้เป็นชื่อหลัก — อนุญาตเฉพาะหมายเหตุ mapping ครั้งเดียว"""
    note = plan_text.split("---")[0]                 # ส่วนหัวก่อน section แรก
    assert "A1→T10" in note
    assert plan_text.count("A1") == note.count("A1"), "A1 ต้องอยู่ในหมายเหตุเท่านั้น"
    for legacy in ("### A1", "### A2", "### A3", "### A4"):
        assert legacy not in plan_text


def test_repetition_requirements_are_stated(plan_text):
    assert "5 repetitions" in plan_text
    assert "Weight Set A, B, C" in plan_text


def test_plan_forbids_overclaiming(plan_text):
    """ไม่มี manual baseline -> ห้ามอ้างว่าลดเวลาได้กี่ %"""
    assert "manual baseline" in plan_text
    assert "ลดเวลาตอบสนองได้ X%" in plan_text       # เขียนไว้เป็นข้อห้าม


def test_t10_scope_is_limited(plan_text):
    assert "false positive 0%" in plan_text          # ระบุว่า *ไม่ใช่* ข้อพิสูจน์นั้น


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
