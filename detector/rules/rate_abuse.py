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
