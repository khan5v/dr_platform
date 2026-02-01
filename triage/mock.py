"""Mock triage engine — deterministic alert classification without LLM calls.

Produces realistic triage output based on rule severity and evidence,
allowing the full pipeline to run end-to-end in Docker without an API key.
In production, this serves as the fallback when the LLM API is unavailable
— a degraded-but-functional triage path (NIST SP 800-61: "maintain
detection capability even when automated analysis is degraded").

Response tiers follow the Bronze/Silver/Gold model:
  - Gold:   Confirmed threat, immediate escalation
  - Silver: Likely threat, investigation queue
  - Bronze: Low confidence, auto-acknowledge
"""


# ---------------------------------------------------------------------------
# Per-rule reasoning templates — makes demo output readable
# ---------------------------------------------------------------------------
_REASONING = {
    "rate_abuse": {
        "true_positive": (
            "Sustained request rate of {eps} req/s with {rl} rate-limit hits "
            "in a 60-second window indicates automated tooling rather than "
            "human interaction.  Rate-limit hit ratio suggests intentional "
            "limit-pushing.  Recommend throttling and investigation."
        ),
        "needs_investigation": (
            "Elevated request rate detected but within borderline range.  "
            "Could be a legitimate power user with a burst workload or a "
            "misconfigured integration.  Needs analyst review of request "
            "patterns and user history."
        ),
    },
    "prompt_injection": {
        "true_positive": (
            "Cluster of {n} safety triggers in 5 minutes with trigger types "
            "{types} indicates deliberate adversarial probing.  Block rate "
            "of {br}% — {unblocked} payloads may have bypassed safety "
            "filters.  Immediate escalation required."
        ),
        "needs_investigation": (
            "Multiple safety triggers detected but volume is borderline.  "
            "Could be a developer testing content moderation or a user "
            "accidentally hitting safety boundaries.  Review trigger types "
            "and user history."
        ),
    },
    "token_abuse": {
        "true_positive": (
            "Average input tokens of {avg}K with {cache}% cache hit rate "
            "across {n} requests.  Near-max context with no caching is the "
            "fingerprint of denial-of-wallet attacks or context-window data "
            "exfiltration.  Models used: {models}."
        ),
        "needs_investigation": (
            "High token usage detected but cache rate suggests some "
            "legitimate usage patterns.  Could be a research workload "
            "with large documents or a RAG pipeline without caching enabled."
        ),
    },
}

_ACTIONS = {
    "gold": {
        "rate_abuse": [
            "Apply temporary rate limit override (50% reduction) for user",
            "Page on-call engineer for review",
            "Preserve request logs for forensic analysis",
        ],
        "prompt_injection": [
            "Temporarily suspend API access for user pending review",
            "Page security on-call — potential active attack",
            "Snapshot safety trigger payloads for threat intelligence",
        ],
        "token_abuse": [
            "Apply token budget cap for user (50K max input tokens)",
            "Flag account for billing review",
            "Notify account owner of anomalous usage",
        ],
    },
    "silver": {
        "rate_abuse": [
            "Add user to monitoring watchlist for 24 hours",
            "Review request patterns for automation signatures",
        ],
        "prompt_injection": [
            "Queue for analyst review within 1 hour",
            "Cross-reference user with known threat actor indicators",
        ],
        "token_abuse": [
            "Queue for analyst review of token usage patterns",
            "Check if user has legitimate large-context use case on file",
        ],
    },
    "bronze": {
        "rate_abuse": ["Log and continue monitoring"],
        "prompt_injection": ["Log and continue monitoring"],
        "token_abuse": ["Log and continue monitoring"],
    },
}


def mock_triage(alert: dict) -> dict:
    """Classify an alert deterministically based on severity and evidence.

    Tier assignment logic (mirrors what a Tier-1 SOC analyst would decide):
      - Critical severity  → Gold (always escalate prompt injection clusters)
      - High severity + strong evidence  → Gold
      - High severity + borderline evidence  → Silver
      - Low event counts or missing evidence  → Bronze
    """
    rule_id = alert.get("rule_id", "unknown")
    severity = alert.get("severity", "unknown")
    evidence = alert.get("evidence", {})
    event_count = alert.get("event_count", 0)

    # --- Tier assignment ---
    if severity == "critical":
        verdict = "true_positive"
        confidence = "high"
        tier = "gold"
        risk_score = 9
    elif severity == "high" and event_count > 10:
        verdict = "true_positive"
        confidence = "medium"
        tier = "gold"
        risk_score = 7
    elif severity == "high":
        verdict = "needs_investigation"
        confidence = "medium"
        tier = "silver"
        risk_score = 5
    else:
        verdict = "needs_investigation"
        confidence = "low"
        tier = "bronze"
        risk_score = 3

    # --- Reasoning ---
    templates = _REASONING.get(rule_id, {})
    template = templates.get(verdict, templates.get("needs_investigation", ""))
    reasoning = _format_reasoning(template, rule_id, evidence, event_count)

    # --- Recommended actions ---
    actions = _ACTIONS.get(tier, {}).get(rule_id, ["Log and continue monitoring"])

    return {
        "verdict": verdict,
        "confidence": confidence,
        "tier": tier,
        "risk_score": risk_score,
        "reasoning": reasoning,
        "recommended_actions": actions,
    }


def _format_reasoning(template: str, rule_id: str, evidence: dict,
                      event_count: int) -> str:
    """Fill reasoning template with evidence values."""
    if not template:
        return f"Alert from rule {rule_id} with {event_count} events."

    try:
        if rule_id == "rate_abuse":
            return template.format(
                eps=evidence.get("events_per_second", "?"),
                rl=evidence.get("rate_limit_count", "?"),
            )
        elif rule_id == "prompt_injection":
            types = ", ".join(evidence.get("trigger_types", ["unknown"]))
            block_rate = evidence.get("block_rate", 0) * 100
            total = evidence.get("total_triggers", event_count)
            blocked = evidence.get("blocked_count", 0)
            return template.format(
                n=total,
                types=types,
                br=round(block_rate),
                unblocked=total - blocked,
            )
        elif rule_id == "token_abuse":
            avg = evidence.get("avg_input_tokens", 0)
            cache = evidence.get("cache_hit_rate", 0) * 100
            models = ", ".join(evidence.get("models_used", ["unknown"]))
            return template.format(
                avg=round(avg / 1000),
                cache=round(cache, 1),
                n=evidence.get("sample_size", event_count),
                models=models,
            )
    except (KeyError, TypeError, ValueError):
        pass
    return f"Alert from rule {rule_id} with {event_count} events."
