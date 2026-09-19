from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


class CorrelationEngine:

    def __init__(self, window_seconds=10, min_events=5):
        self.window = timedelta(seconds=window_seconds)
        self.min_events = min_events
        self.events = defaultdict(deque)

    def process(self, event):
        src_ip = event.get("src_ip")
        timestamp = event.get("timestamp")

        if not src_ip or not timestamp:
            return None

        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        bucket = self.events[src_ip]
        bucket.append((timestamp, event))

        cutoff = timestamp - self.window

        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.min_events:
            events = [item[1] for item in bucket]

            return {
                "src_ip": src_ip,
                "event_count": len(events),
                "window_seconds": (
                    timestamp - bucket[0][0]
                ).total_seconds(),
                "events": events,
            }

        return None
