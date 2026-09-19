import sys
from security_engine.correlation.engine import CorrelationEngine
from security_engine.ingestion.eve_reader import stream_events


def cprint(text=""):
    """พิมพ์ข้อความโดยบังคับส่ง Carriage Return + Line Feed (\r\n) เพื่อขจัดปัญหาข้อความเยื้องขวา"""
    formatted = str(text).replace("\n", "\r\n") + "\r\n"
    sys.stdout.write(formatted)
    sys.stdout.flush()


def main():
    correlator = CorrelationEngine(
        window_seconds=10,
        min_events=5,
    )

    cprint("=" * 60)
    cprint("[*] SEC01 Phase 4: Correlation Engine Running")
    cprint("[*] Sliding Window: 10s | Minimum Events: 5")
    cprint("=" * 60)

    try:
        for event in stream_events():
            msg = f"[RAW EVENT] {event['timestamp']} | {event['src_ip']} -> {event['dest_ip']} | SID: {event['sid']}"
            cprint(msg)

            pattern = correlator.process(event)

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


if __name__ == "__main__":
    main()
