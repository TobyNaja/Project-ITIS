import argparse
import os
import sys
from pathlib import Path


def _load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader (no dependency). Does not override existing env."""
    p = path or (Path(__file__).resolve().parent / ".env")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip("'\"")
        if k and k not in os.environ:
            os.environ[k] = v


_load_dotenv()  # must run before importing eve_reader (it reads env at import)

from security_engine.correlation.engine import CorrelationEngine
from security_engine.ingestion.eve_reader import stream_events


def cprint(text=""):
    """พิมพ์ข้อความโดยบังคับส่ง Carriage Return + Line Feed (\r\n) เพื่อขจัดปัญหาข้อความเยื้องขวา"""
    formatted = str(text).replace("\n", "\r\n") + "\r\n"
    sys.stdout.write(formatted)
    sys.stdout.flush()


def fmt_ts(ts):
    try:
        return ts.isoformat()
    except Exception:
        return str(ts)


def main():
    ap = argparse.ArgumentParser(description="SEC01 Phase 4: Correlation Engine")
    ap.add_argument("--window", type=float,
                    default=float(os.environ.get("WINDOW_SECONDS", 10)),
                    help="sliding window seconds")
    ap.add_argument("--min-events", type=int,
                    default=int(os.environ.get("MIN_EVENTS", 5)),
                    help="minimum events to alert")
    ap.add_argument("--cooldown", type=float,
                    default=(float(os.environ["COOLDOWN_SECONDS"])
                             if os.environ.get("COOLDOWN_SECONDS") else None),
                    help="suppress repeat alerts per IP (default: = window)")
    ap.add_argument("--host", default=None, help="override PFSENSE_HOST")
    ap.add_argument("--eve-path", default=None, help="override EVE_PATH")
    args = ap.parse_args()

    correlator = CorrelationEngine(
        window_seconds=args.window,
        min_events=args.min_events,
        cooldown_seconds=args.cooldown,
    )

    cprint("=" * 60)
    cprint("[*] SEC01 Phase 4: Correlation Engine Running")
    cprint(f"[*] Sliding Window: {args.window}s | Minimum Events: {args.min_events}")
    cprint("=" * 60)

    kwargs = {}
    if args.host:
        kwargs["host"] = args.host
    if args.eve_path:
        kwargs["eve_path"] = args.eve_path

    try:
        for event in stream_events(**kwargs):
            if not event:
                continue
            ts = fmt_ts(event.get("timestamp"))
            src = event.get("src_ip", "?")
            dst = event.get("dest_ip", "?")
            sid = event.get("signature_id", "?")
            sev = event.get("severity", "?")
            msg = f"[RAW EVENT] {ts} | {src} -> {dst} | SID: {sid} sev={sev}"
            cprint(msg)

            try:
                pattern = correlator.process(event)
            except Exception as exc:
                cprint(f"[WARN] correlation skipped event: {exc}")
                continue

            if pattern:
                cprint("\n" + "!" * 60)
                cprint(
                    f"[CORRELATION MATCHED] IP: {pattern['src_ip']} | "
                    f"Count: {pattern['event_count']} | "
                    f"Window: {pattern['window_seconds']:.2f}s"
                )
                cprint("!" * 60 + "\n")

    except KeyboardInterrupt:
        cprint("\n[*] Stopping Phase 4 Correlation Engine.")
    except (ValueError, RuntimeError) as exc:
        # Config errors (e.g. CHANGE_ME placeholder) or ssh startup failure
        cprint(f"[FATAL] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
