from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


class CorrelationEngine:
    """
    Correlate normalized security events by source IP
    using a sliding time window.
    """

    def __init__(
        self,
        window_seconds=10,
        min_events=5,
        cooldown_seconds=None,
    ):
        self.window = timedelta(seconds=window_seconds)
        self.min_events = min_events

        # Suppress repeated correlation alerts.
        # Default cooldown equals the correlation window.
        self.cooldown = timedelta(
            seconds=(
                cooldown_seconds
                if cooldown_seconds is not None
                else window_seconds
            )
        )

        self.events = defaultdict(deque)
        self.last_alert = {}

    def _parse_time(self, timestamp):
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                return None

        if not isinstance(timestamp, datetime):
            return None
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp

    def _cleanup(self, now):
        """
        Remove inactive source IP state to prevent
        unbounded memory growth.
        """
        expiry = now - self.window - self.cooldown
        for src_ip in list(self.events.keys()):
            bucket = self.events[src_ip]

            if not bucket or bucket[-1][0] < expiry:
                del self.events[src_ip]
                self.last_alert.pop(src_ip, None)

    def process(self, event):
        src_ip = event.get("src_ip")
        timestamp = self._parse_time(
            event.get("timestamp")
        )

        if not src_ip or timestamp is None:
            return None

        bucket = self.events[src_ip]
        bucket.append((timestamp, event))
        cutoff = timestamp - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        if not bucket:
            self.events.pop(src_ip, None)
            self.last_alert.pop(src_ip, None)
            return None

        self._cleanup(timestamp)

        if len(bucket) < self.min_events:
            return None

        last_alert = self.last_alert.get(src_ip)

        if (
            last_alert is not None
            and timestamp - last_alert < self.cooldown
        ):
            return None

        self.last_alert[src_ip] = timestamp

        events = [item[1] for item in bucket]

        return {
            "src_ip": src_ip,
            "event_count": len(events),
            "window_seconds": (
                timestamp - bucket[0][0]
            ).total_seconds(),
            "events": events,
        }