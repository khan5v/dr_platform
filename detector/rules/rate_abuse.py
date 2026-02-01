"""Rate abuse — sustained high request volume from a single user.

Catches automated scraping, credential-stuffing proxies, and runaway loops.
Fires when a user generates >60 API requests + rate-limit hits in a 1-minute
sliding window.
"""

from detector.rules import Rule


class RateAbuse(Rule):
    id = "rate_abuse"
    name = "API Rate Abuse"
    severity = "high"
    window_seconds = 60

    def match(self, event):
        return event["event_type"] in ("api_request", "rate_limit_event")

    def trigger(self, events):
        return len(events) > 60

    def evidence(self, events):
        api_reqs = sum(1 for e in events if e.get("event_type") == "api_request")
        rate_limits = sum(1 for e in events if e.get("event_type") == "rate_limit_event")
        timestamps = [e.get("timestamp", 0) for e in events]
        span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1
        return {
            "api_request_count": api_reqs,
            "rate_limit_count": rate_limits,
            "events_per_second": round(len(events) / max(span, 1), 2),
        }
