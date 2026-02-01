"""Tests for triage prompt construction."""

from triage.prompt import build_system_prompt, build_triage_prompt, TIER_DESCRIPTIONS


class TestSystemPrompt:
    def test_returns_nonempty_string(self):
        prompt = build_system_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 100

    def test_mentions_tiers(self):
        prompt = build_system_prompt()
        assert "GOLD" in prompt
        assert "SILVER" in prompt
        assert "BRONZE" in prompt

    def test_requests_json_output(self):
        prompt = build_system_prompt()
        assert "JSON" in prompt


class TestTriagePrompt:
    def _alert(self, rule_id="rate_abuse", severity="high", **extra):
        alert = {
            "rule_id": rule_id,
            "rule_name": "Test Rule",
            "severity": severity,
            "user_id": "user_001",
            "org_id": "org_001",
            "timestamp": 1700000000.0,
            "window_seconds": 60,
            "event_count": 62,
            "evidence": {
                "api_request_count": 44,
                "rate_limit_count": 18,
                "events_per_second": 1.03,
            },
        }
        alert.update(extra)
        return alert

    def test_includes_rule_id(self):
        prompt = build_triage_prompt(self._alert())
        assert "rate_abuse" in prompt

    def test_includes_user_id(self):
        prompt = build_triage_prompt(self._alert())
        assert "user_001" in prompt

    def test_includes_evidence(self):
        prompt = build_triage_prompt(self._alert())
        assert "api_request_count" in prompt
        assert "rate_limit_count" in prompt

    def test_includes_rule_context(self):
        prompt = build_triage_prompt(self._alert())
        assert "60 API requests" in prompt or "sliding window" in prompt

    def test_prompt_injection_context(self):
        prompt = build_triage_prompt(self._alert(
            rule_id="prompt_injection", severity="critical",
            evidence={"trigger_types": ["prompt_injection"], "blocked_count": 3},
        ))
        assert "safety" in prompt.lower()

    def test_token_abuse_context(self):
        prompt = build_triage_prompt(self._alert(
            rule_id="token_abuse",
            evidence={"avg_input_tokens": 160000, "cache_hit_rate": 0.0},
        ))
        assert "150K" in prompt or "cache" in prompt.lower()

    def test_requests_structured_output(self):
        prompt = build_triage_prompt(self._alert())
        assert "verdict" in prompt
        assert "tier" in prompt
        assert "risk_score" in prompt

    def test_unknown_rule_doesnt_crash(self):
        prompt = build_triage_prompt(self._alert(rule_id="unknown_rule"))
        assert "unknown_rule" in prompt


class TestTierDescriptions:
    def test_all_tiers_defined(self):
        assert "gold" in TIER_DESCRIPTIONS
        assert "silver" in TIER_DESCRIPTIONS
        assert "bronze" in TIER_DESCRIPTIONS
