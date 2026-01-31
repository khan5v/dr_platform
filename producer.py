"""Claude API telemetry event generator.

Simulates realistic API traffic with configurable normal and abusive user
profiles. Event schemas are modeled after actual Claude Messages API fields
(request_id, model, input/output tokens, cache tokens, stop_reason, etc.).

Usage:
    python producer.py
    python producer.py --normal 20 --rate-abusers 2 --injection-abusers 2 --token-abusers 1
    python producer.py --eps 100 --topic raw-api-events
"""

import argparse
import json
import random
import signal
import time
import uuid
from dataclasses import dataclass

from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient, NewTopic

MODELS = [
    "claude-sonnet-4-20250514",
    "claude-haiku-35-20241022",
    "claude-opus-4-20250115",
]
STOP_REASONS = ["end_turn", "max_tokens", "stop_sequence", "tool_use"]

running = True


def _shutdown(sig, frame):
    global running
    print("\nShutting down generator...")
    running = False


signal.signal(signal.SIGINT, _shutdown)   # Ctrl+C (local dev)
signal.signal(signal.SIGTERM, _shutdown)  # docker stop / k8s pod termination


# ---------------------------------------------------------------------------
# User profiles
# ---------------------------------------------------------------------------

@dataclass
class User:
    user_id: str
    org_id: str
    role: str  # normal | rate_abuser | prompt_injector | token_abuser
    events_per_min: float
    input_tokens_lo: int
    input_tokens_hi: int
    cache_hit_rate: float
    safety_trigger_rate: float  # fraction of events that become safety_trigger
    rate_limit_rate: float      # fraction of events that become rate_limit_event


def _create_users(n_normal, n_rate_abusers, n_injectors, n_token_abusers):
    """Build the user pool. Each user gets a stable org assignment."""
    users = []
    uid = 0
    orgs = [f"org_{i:03d}" for i in range(1, 6)]
    normal_rpm = {"light": (3, 10), "regular": (20, 50), "power": (60, 150)}
    normal_archetypes = list(normal_rpm.keys())

    # --- Normal users: light / regular / power archetypes ---
    for _ in range(n_normal):
        uid += 1
        archetype = random.choice(normal_archetypes)
        rpm = normal_rpm[archetype]
        users.append(User(
            user_id=f"user_{uid:04d}", org_id=random.choice(orgs), role="normal",
            events_per_min=random.uniform(*rpm),
            input_tokens_lo=100, input_tokens_hi=8000,
            cache_hit_rate=random.uniform(0.25, 0.60),
            safety_trigger_rate=0.005, rate_limit_rate=0.0,
        ))

    # --- Rate abusers: high RPM, frequently hitting 429s ---
    for _ in range(n_rate_abusers):
        uid += 1
        users.append(User(
            user_id=f"user_{uid:04d}", org_id=random.choice(orgs), role="rate_abuser",
            events_per_min=random.uniform(150, 300),
            input_tokens_lo=100, input_tokens_hi=2000,
            cache_hit_rate=random.uniform(0.05, 0.15),
            safety_trigger_rate=0.01, rate_limit_rate=0.3,
        ))

    # --- Prompt injectors: moderate rate, most requests flagged ---
    for _ in range(n_injectors):
        uid += 1
        users.append(User(
            user_id=f"user_{uid:04d}", org_id=random.choice(orgs), role="prompt_injector",
            events_per_min=random.uniform(20, 60),
            input_tokens_lo=500, input_tokens_hi=10000,
            cache_hit_rate=0.02,
            safety_trigger_rate=0.6, rate_limit_rate=0.0,
        ))

    # --- Token abusers: near-max context, zero cache, sustained ---
    for _ in range(n_token_abusers):
        uid += 1
        users.append(User(
            user_id=f"user_{uid:04d}", org_id=random.choice(orgs), role="token_abuser",
            events_per_min=random.uniform(10, 30),
            input_tokens_lo=150_000, input_tokens_hi=199_000,
            cache_hit_rate=0.0,
            safety_trigger_rate=0.02, rate_limit_rate=0.05,
        ))

    return users


# ---------------------------------------------------------------------------
# Event generation
# ---------------------------------------------------------------------------

def _make_event(user: User) -> dict:
    """Generate a single event for a user based on their profile probabilities."""
    roll = random.random()
    ts = time.time()
    rid = f"req_{uuid.uuid4().hex[:12]}"

    # Safety trigger
    if roll < user.safety_trigger_rate:
        return {
            "event_type": "safety_trigger",
            "timestamp": ts,
            "request_id": rid,
            "user_id": user.user_id,
            "org_id": user.org_id,
            "model": random.choice(MODELS),
            "trigger_type": random.choice(
                ["prompt_injection", "policy_violation", "harmful_content"]
            ),
            "input_tokens": random.randint(user.input_tokens_lo, user.input_tokens_hi),
            "blocked": random.random() < 0.7,
        }

    # Rate limit hit
    if roll < user.safety_trigger_rate + user.rate_limit_rate:
        return {
            "event_type": "rate_limit_event",
            "timestamp": ts,
            "request_id": rid,
            "user_id": user.user_id,
            "org_id": user.org_id,
            "limit_type": random.choice(["rpm", "tpm"]),
            "current_value": int(user.events_per_min * random.uniform(1.0, 1.5)),
            "limit_value": 60,
        }

    # Normal API request
    input_tokens = random.randint(user.input_tokens_lo, user.input_tokens_hi)
    cache_hit = random.random() < user.cache_hit_rate
    cache_read = int(input_tokens * random.uniform(0.3, 0.8)) if cache_hit else 0

    return {
        "event_type": "api_request",
        "timestamp": ts,
        "request_id": rid,
        "user_id": user.user_id,
        "org_id": user.org_id,
        "model": random.choice(MODELS),
        "input_tokens": input_tokens,
        "output_tokens": random.randint(50, 4000),
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": input_tokens - cache_read if not cache_hit else 0,
        "status_code": 200,
        "stop_reason": random.choice(STOP_REASONS),
        "latency_ms": random.randint(200, 3000),
    }


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def _ensure_topics(bootstrap_servers, topics):
    """Create Kafka topics if they don't already exist."""
    admin = AdminClient({"bootstrap.servers": bootstrap_servers})
    new_topics = [NewTopic(t, num_partitions=3, replication_factor=3) for t in topics]
    fs = admin.create_topics(new_topics)
    for topic, f in fs.items():
        try:
            f.result()
            print(f"Created topic '{topic}'")
        except Exception as e:
            if "TOPIC_ALREADY_EXISTS" in str(e):
                print(f"Topic '{topic}' already exists")
            else:
                raise


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Claude API telemetry generator")
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--topic", default="raw-api-events")
    parser.add_argument("--normal", type=int, default=8)
    parser.add_argument("--rate-abusers", type=int, default=1)
    parser.add_argument("--injection-abusers", type=int, default=1)
    parser.add_argument("--token-abusers", type=int, default=1)
    parser.add_argument("--eps", type=float, default=50, help="Target events/sec")
    args = parser.parse_args()

    users = _create_users(
        args.normal, args.rate_abusers, args.injection_abusers, args.token_abusers,
    )
    weights = [u.events_per_min for u in users]

    print(f"Generating to topic '{args.topic}' at ~{args.eps} events/sec")
    print(f"Users: {len(users)} total")
    for u in users:
        print(f"  {u.user_id}  {u.role:<18s} ~{u.events_per_min:>6.0f} epm  org={u.org_id}")

    _ensure_topics(args.bootstrap_servers, [args.topic])

    producer = Producer({
        "bootstrap.servers": args.bootstrap_servers,
        "acks": "all",
        "client.id": "api-event-generator",
    })

    count = 0
    delay = 1.0 / args.eps

    while running:
        user = random.choices(users, weights=weights, k=1)[0]
        event = _make_event(user)

        producer.produce(
            topic=args.topic,
            key=event["user_id"].encode(),
            value=json.dumps(event),
        )
        producer.poll(0)

        count += 1
        if count % 500 == 0:
            print(f"  ... {count} events produced")

        time.sleep(delay)

    producer.flush()
    print(f"Done. {count} events produced.")


if __name__ == "__main__":
    main()
