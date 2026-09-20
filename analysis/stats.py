"""
analysis/stats.py — Phase 12.10 สถิติ (offline, ไม่แตะ pipeline/pfSense)

คำนวณเฉพาะที่ protocol ล็อก: n, median, Q1, Q3, IQR, min, max, p95
*** ไม่มี accuracy / FPR / detection rate ***
ใช้ statistics ของ stdlib — ไม่ต้องพึ่ง numpy
"""
import statistics


def percentile(sorted_vals, p):
    """p ใน [0,100] — linear interpolation (เท่ากับ numpy percentile ค่า default)"""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac


def summarize(values):
    """คืน dict สถิติของ list ตัวเลข; ถ้าว่างคืน n=0 พร้อม field เป็น None"""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return {"n": 0, "median": None, "q1": None, "q3": None,
                "iqr": None, "min": None, "max": None, "p95": None}
    q1 = percentile(vals, 25)
    q3 = percentile(vals, 75)
    return {
        "n": len(vals),
        "median": statistics.median(vals),
        "q1": q1,
        "q3": q3,
        "iqr": (q3 - q1) if (q1 is not None and q3 is not None) else None,
        "min": vals[0],
        "max": vals[-1],
        "p95": percentile(vals, 95),
    }