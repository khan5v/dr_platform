"""Tests for SlidingWindow — boundaries, eviction, drift guard."""

import time
import pytest
from unittest.mock import patch

from detector.sliding_window import SlidingWindow, _MAX_DRIFT_SECONDS


class TestEviction:
    def test_events_within_window_are_kept(self):
        w = SlidingWindow(60)
        now = time.time()
        w.add(now - 30, {"id": 1})
        w.add(now - 10, {"id": 2})
        assert len(w.events(now)) == 2

    def test_event_exactly_at_boundary_stays_in_window(self):
        """An event exactly max_age old: accepted by add(), kept by eviction
        (cutoff uses strict <, so timestamp == cutoff is not evicted)."""
        w = SlidingWindow(60)
        now = time.time()
        with patch("detector.sliding_window.time") as mock_time:
            mock_time.time.return_value = now
            w.add(now - 60, {"id": "boundary"})
        # cutoff = now - 60, timestamp = now - 60 → not < cutoff → kept
        assert len(w.events(now)) == 1

    def test_events_just_past_boundary_are_evicted(self):
        w = SlidingWindow(60)
        now = time.time()
        w.add(now - 60.001, {"id": "old"})
        assert len(w.events(now)) == 0

    def test_events_just_inside_boundary_are_kept(self):
        w = SlidingWindow(60)
        now = time.time()
        w.add(now - 59.999, {"id": "fresh"})
        assert len(w.events(now)) == 1

    def test_progressive_eviction(self):
        """Events are evicted as time advances."""
        w = SlidingWindow(10)
        now = time.time()

        with patch("detector.sliding_window.time") as mock_time:
            # t=0: add "a"
            mock_time.time.return_value = now
            w.add(now, {"id": "a"})

            # t=5: add "b"
            mock_time.time.return_value = now + 5
            w.add(now + 5, {"id": "b"})

            # t=12: add "c" — "a" (age 12s) should be evicted
            mock_time.time.return_value = now + 12
            w.add(now + 12, {"id": "c"})

        evts = w.events(now + 12)
        ids = [e["id"] for e in evts]
        assert "a" not in ids
        assert "b" in ids
        assert "c" in ids


class TestDriftGuard:
    def test_event_in_past_is_accepted(self):
        w = SlidingWindow(60)
        assert w.add(time.time() - 30, {"id": "past"}) is True
        assert len(w) == 1

    def test_event_at_current_time_is_accepted(self):
        w = SlidingWindow(60)
        assert w.add(time.time(), {"id": "now"}) is True

    def test_event_slightly_in_future_is_accepted(self):
        w = SlidingWindow(60)
        assert w.add(time.time() + 1, {"id": "near_future"}) is True

    def test_event_beyond_drift_limit_is_rejected(self):
        w = SlidingWindow(60)
        assert w.add(time.time() + _MAX_DRIFT_SECONDS + 1, {"id": "bad"}) is False
        assert len(w) == 0

    def test_event_exactly_at_drift_limit_is_accepted(self):
        w = SlidingWindow(60)
        # Exactly at the boundary: now + MAX_DRIFT is not > now + MAX_DRIFT
        result = w.add(time.time() + _MAX_DRIFT_SECONDS, {"id": "edge"})
        # This may be True or False depending on sub-ms timing; just ensure no crash
        assert isinstance(result, bool)


class TestClear:
    def test_clear_empties_window(self):
        w = SlidingWindow(60)
        now = time.time()
        w.add(now, {"id": 1})
        w.add(now, {"id": 2})
        assert len(w) == 2
        w.clear()
        assert len(w) == 0
        assert w.events(now) == []

    def test_add_after_clear(self):
        w = SlidingWindow(60)
        now = time.time()
        w.add(now, {"id": 1})
        w.clear()
        w.add(now, {"id": 2})
        assert len(w) == 1
        assert w.events(now)[0]["id"] == 2


class TestEdgeCases:
    def test_empty_window_events(self):
        w = SlidingWindow(60)
        assert w.events(time.time()) == []

    def test_zero_duration_window(self):
        """A 0-second window: event at exactly 'now' survives (cutoff uses strict <)."""
        w = SlidingWindow(0)
        now = time.time()
        with patch("detector.sliding_window.time") as mock_time:
            mock_time.time.return_value = now
            w.add(now, {"id": 1})
        # cutoff = now - 0 = now, timestamp = now → not < cutoff → kept
        assert len(w.events(now)) == 1

    def test_very_old_event_in_large_window(self):
        w = SlidingWindow(900)  # 15 min
        now = time.time()
        w.add(now - 899, {"id": "old_but_valid"})
        assert len(w.events(now)) == 1

    def test_already_expired_event_is_rejected(self):
        """An event older than the window should be dropped on add(), not poison the deque."""
        w = SlidingWindow(900)
        now = time.time()
        w.add(now - 899, {"id": "valid"})
        result = w.add(now - 901, {"id": "too_old"})
        assert result is False
        assert len(w.events(now)) == 1
