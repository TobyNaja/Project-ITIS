r"""
conftest.py (repo root) — Phase 12

pytest โหลดไฟล์นี้อัตโนมัติก่อน collect test และใส่โฟลเดอร์ที่มันอยู่ (repo root)
ลงใน sys.path ให้ด้วย ทำให้ test ใต้ tests/ import โมดูลระดับ root ได้
เช่น `import run_experiment` — โดยไม่ต้องตั้ง PYTHONPATH เอง

วางไฟล์นี้ที่ repo root: D:\IT\Year 3\ITIS\Project-ITIS\conftest.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)