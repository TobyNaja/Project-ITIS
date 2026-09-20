"""
tests/test_analyzer.py — Phase 12.10 Analyzer + stats (offline, synthetic JSONL)

พิสูจน์ว่า analyzer ไม่ silently drop และคำนวณสถิติถูก
"""
import json

from analysis.stats import summarize, percentile
from analysis import analyze as az


# ---- stats ----
def test_summarize_basic():
    s = summarize([1, 2, 3, 4, 5])
    assert s["n"] == 5
    assert s["median"] == 3
    assert s["min"] == 1
    assert s["max"] == 5


def test_summarize_ignores_none():
    s = summarize([1, None, 3, None, 5])
    assert s["n"] == 3


def test_summarize_empty():
    s = summarize([])
    assert s["n"] == 0
    assert s["median"] is None


def test_percentile_p95():
    vals = list(range(1, 101))   # 1..100
    assert 95 <= percentile(vals, 95) <= 96


# ---- analyzer validation ----
def _block_rec(scenario, trial, det=0.01, dec=0.02, enf=0.26, e2e=0.30):
    return {"scenario_id": scenario, "trial_no": trial, "decision": "BLOCK",
            "detection_s": det, "decision_s": dec, "enforcement_s": enf,
            "end_to_end_s": e2e}


def _write_jsonl(tmp_path, records):
    p = tmp_path / "traces.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return str(p)


def test_all_valid(tmp_path):
    recs = [_block_rec("B1", i) for i in range(1, 6)]
    path = _write_jsonl(tmp_path, recs)
    res = az.analyze(path, str(tmp_path / "out"))
    assert res["counts"]["total"] == 5
    assert res["counts"]["valid"] == 5
    assert res["counts"]["invalid"] == 0
    assert res["summary"]["end_to_end_s"]["n"] == 5


def test_non_block_excluded_not_dropped(tmp_path):
    # ALERT record ต้องถูกนับเป็น invalid (excluded) ไม่ใช่หายเงียบ
    recs = [_block_rec("B1", 1),
            {"scenario_id": "A3", "trial_no": 1, "decision": "ALERT"}]
    path = _write_jsonl(tmp_path, recs)
    res = az.analyze(path, str(tmp_path / "out"))
    assert res["counts"]["total"] == 2
    assert res["counts"]["valid"] == 1
    assert res["counts"]["invalid"] == 1          # ALERT ไม่ปนกับ BLOCK latency


def test_missing_t5_invalid(tmp_path):
    bad = _block_rec("B1", 1)
    bad["end_to_end_s"] = None
    bad["enforcement_s"] = None                    # t5 ขาด
    path = _write_jsonl(tmp_path, [bad])
    res = az.analyze(path, str(tmp_path / "out"))
    assert res["counts"]["valid"] == 0
    assert res["counts"]["invalid"] == 1


def test_negative_latency_invalid(tmp_path):
    bad = _block_rec("B1", 1, e2e=-0.5)            # เวลาติดลบ = trace เสีย
    path = _write_jsonl(tmp_path, [bad])
    res = az.analyze(path, str(tmp_path / "out"))
    assert res["counts"]["invalid"] == 1


def test_missing_scenario_id_invalid(tmp_path):
    bad = _block_rec(None, 1)
    path = _write_jsonl(tmp_path, [bad])
    res = az.analyze(path, str(tmp_path / "out"))
    assert res["counts"]["invalid"] == 1


def test_counts_add_up(tmp_path):
    # total = valid + invalid เสมอ (ไม่มีข้อมูลหาย)
    recs = [_block_rec("B1", 1), _block_rec("B1", 2),
            {"scenario_id": "A3", "trial_no": 1, "decision": "ALERT"},
            _block_rec("B1", 3, e2e=-1)]
    path = _write_jsonl(tmp_path, recs)
    res = az.analyze(path, str(tmp_path / "out"))
    c = res["counts"]
    assert c["total"] == c["valid"] + c["invalid"]
    assert c["total"] == 4


def test_output_files_written(tmp_path):
    path = _write_jsonl(tmp_path, [_block_rec("B1", 1)])
    out = tmp_path / "out"
    az.analyze(path, str(out))
    assert (out / "validation_report.txt").exists()
    assert (out / "latency_summary.csv").exists()
    assert (out / "latency_summary.json").exists()


def test_duplicate_trial_flagged(tmp_path):
    recs = [_block_rec("B1", 1), _block_rec("B1", 1)]   # trial_no ซ้ำ
    path = _write_jsonl(tmp_path, recs)
    res = az.analyze(path, str(tmp_path / "out"))
    report = (tmp_path / "out" / "validation_report.txt").read_text(encoding="utf-8")
    assert "duplicate_trials : 1" in report


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-v"]))