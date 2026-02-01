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

    def evidence(self, events):
        if not events:
            return {}
        tokens = [e.get("input_tokens", 0) for e in events]
        cache_hits = sum(
            1 for e in events if e.get("cache_read_input_tokens", 0) > 0
        )
        models = list({e.get("model", "unknown") for e in events})
        return {
            "avg_input_tokens": round(sum(tokens) / len(tokens)),
            "max_input_tokens": max(tokens),
            "cache_hit_rate": round(cache_hits / len(events), 3),
            "sample_size": len(events),
            "models_used": models,
        }
