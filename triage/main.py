"""LLM triage service — classifies detection alerts using Claude or mock engine.

Consumes alerts from the detection engine, runs each through an LLM (or
deterministic mock) for classification, and produces structured triage
decisions with Bronze/Silver/Gold response tiers.

This service sits at the boundary between automated detection and human
response — the SOC automation pyramid's Tier-1 analyst layer. In
Anthropic's own SOC (RSA 2025), this pattern reduced investigation time
by 90%: the LLM handles Bronze/Silver classification so human analysts
focus exclusively on Gold-tier escalations.

Usage:
    python -m triage.main --mock
    python -m triage.main --bootstrap-servers kafka-1:29092
"""

import argparse
import json
import os
import signal
import sys
import time

from confluent_kafka import Consumer, Producer, KafkaError
from confluent_kafka.admin import AdminClient, NewTopic

from triage.prompt import build_system_prompt, build_triage_prompt
from triage.mock import mock_triage

_TIER_TAGS = {"gold": "GOLD  ", "silver": "SILVER", "bronze": "BRONZE"}

running = True


def _shutdown(sig, frame):
    global running
    print("\nShutting down triage service...")
    running = False


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


def _ensure_topic(bootstrap_servers, topic):
    """Create the output topic if it doesn't already exist."""
    admin = AdminClient({"bootstrap.servers": bootstrap_servers})
    fs = admin.create_topics([NewTopic(topic, num_partitions=3, replication_factor=3)])
    for t, f in fs.items():
        try:
            f.result()
            print(f"Created topic '{t}'")
        except Exception as e:
            if "TOPIC_ALREADY_EXISTS" in str(e):
                print(f"Topic '{t}' already exists")
            else:
                raise


def _read_api_key() -> str | None:
    """Read the Anthropic API key, preferring Docker secrets over env vars.

    Docker Compose secrets are mounted as files at /run/secrets/<name>.
    This is the recommended approach for production containers — secrets
    never appear in docker inspect, environment dumps, or process listings.
    Falls back to ANTHROPIC_API_KEY env var for local development.
    """
    secrets_path = "/run/secrets/anthropic_api_key"
    try:
        with open(secrets_path) as f:
            key = f.read().strip()
            if key:
                return key
    except FileNotFoundError:
        pass
    return os.environ.get("ANTHROPIC_API_KEY")


def _triage_with_llm(alert: dict, model: str) -> dict:
    """Call the Anthropic API for real LLM triage."""
    try:
        import anthropic
    except ImportError:
        print("anthropic package not installed — falling back to mock",
              file=sys.stderr)
        return mock_triage(alert)

    api_key = _read_api_key()
    if not api_key:
        print("No API key found (checked /run/secrets/anthropic_api_key "
              "and ANTHROPIC_API_KEY env) — falling back to mock",
              file=sys.stderr)
        return mock_triage(alert)

    client = anthropic.Anthropic(api_key=api_key)
    system_prompt = build_system_prompt()
    user_prompt = build_triage_prompt(alert)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=512,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = response.content[0].text
        return json.loads(text)
    except (json.JSONDecodeError, anthropic.APIError, IndexError) as e:
        print(f"LLM triage failed ({e}), falling back to mock", file=sys.stderr)
        return mock_triage(alert)


def main():
    parser = argparse.ArgumentParser(description="LLM triage service")
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--input-topic", default="alerts")
    parser.add_argument("--output-topic", default="triage-results")
    parser.add_argument("--group-id", default="triage-engine")
    parser.add_argument(
        "--mock", action="store_true", default=False,
        help="Use deterministic mock triage instead of Claude API",
    )
    parser.add_argument(
        "--anthropic-model", default="claude-haiku-4-5-20251001",
        help="Claude model for LLM triage (default: Haiku for speed/cost)",
    )
    args = parser.parse_args()

    _ensure_topic(args.bootstrap_servers, args.output_topic)

    consumer = Consumer({
        "bootstrap.servers": args.bootstrap_servers,
        "group.id": args.group_id,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([args.input_topic])

    producer = Producer({"bootstrap.servers": args.bootstrap_servers})

    mode = "mock" if args.mock else f"llm ({args.anthropic_model})"
    consumed = 0
    produced = 0

    print(f"Triage service started  mode={mode}  "
          f"input={args.input_topic}  output={args.output_topic}")

    try:
        while running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"Consumer error: {msg.error()}", file=sys.stderr)
                continue

            try:
                alert = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            consumed += 1

            # --- Triage ---
            if args.mock:
                triage_result = mock_triage(alert)
                model_used = "mock"
            else:
                triage_result = _triage_with_llm(alert, args.anthropic_model)
                model_used = args.anthropic_model

            # --- Assemble output ---
            output = {
                "alert": alert,
                "triage": triage_result,
                "model": model_used,
                "triage_timestamp": time.time(),
            }

            # --- Produce ---
            user_id = alert.get("user_id", "unknown")
            producer.produce(
                args.output_topic,
                key=user_id.encode(),
                value=json.dumps(output).encode(),
            )
            produced += 1

            tier = triage_result.get("tier", "?")
            tier_tag = _TIER_TAGS.get(tier, tier)
            verdict = triage_result.get("verdict", "?")
            confidence = triage_result.get("confidence", "?")
            risk = triage_result.get("risk_score", "?")

            print(f"TRIAGE [{tier_tag}]  rule={alert.get('rule_id', '?'):<20s} "
                  f"user={user_id:<12s} verdict={verdict:<20s} "
                  f"confidence={confidence:<8s} risk={risk}")

            if consumed % 100 == 0:
                producer.flush()
    finally:
        producer.flush()
        consumer.close()
        print(f"Triage done. {consumed} alerts consumed, {produced} decisions produced.")


if __name__ == "__main__":
    main()
