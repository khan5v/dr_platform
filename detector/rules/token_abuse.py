"""Token stuffing — near-max context with no caching.

Legitimate high-token users almost always leverage prompt caching.  A user
consistently sending >150K input tokens with <5% cache hit rate is likely
stuffing context to maximize compute cost (denial-of-wallet) or exfiltrating
training-style data through the context window.

Requires a minimum of 5 events in the window to avoid false positives from
a single large request.
"""

from detector.rules import Rule


class TokenAbuse(Rule):
    id = "token_abuse"
    name = "Token Stuffing"
    severity = "high"
    window_seconds = 900

    def match(self, event):
        return event["event_type"] == "api_request"

    def trigger(self, events):
        if len(events) < 5:
            return False
        avg_tokens = sum(e.get("input_tokens", 0) for e in events) / len(events)
        cache_hits = sum(
            1 for e in events if e.get("cache_read_input_tokens", 0) > 0
        )
        cache_rate = cache_hits / len(events)
        return avg_tokens > 150_000 and cache_rate < 0.05
