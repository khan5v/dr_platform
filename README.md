# DR Platform

Real-time Claude API abuse detection platform — streaming telemetry through Kafka into a rule-based detection engine.

## Architecture

```
generator/          → Simulates Claude API traffic (normal + abusive users)
    main.py             Kafka producer with configurable user profiles

detector/           → Detection engine and rules
    main.py             Kafka consumer: reads events, runs engine, produces alerts
    engine.py           Core engine: routes events to rules via sliding windows
    sliding_window.py   Time-based window with drift guard
    rules/              Detection-as-code (Python classes, not YAML)
        rate_abuse.py       >60 requests in 60s
        prompt_injection.py >3 safety triggers in 5min
        token_abuse.py      >150K avg tokens + <5% cache in 15min
    tests/              Unit + integration tests

docker/
    Dockerfile          Shared image for all services
    docker-compose.yml  Full stack: 3-broker Kafka + generator + detector
```

## Data flow

```
[generator] → raw-api-events (3 partitions) → [detector ×3] → alerts topic
```

Each detector replica owns a partition. Events are keyed by `user_id`, so a user's events always land on the same partition — keeping per-user sliding windows consistent.

## Setup

```bash
chmod +x setup.sh && ./setup.sh
```

## Run (Docker)

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Starts ZooKeeper, 3 Kafka brokers, Kafka UI, the generator (50 eps), and 3 detector replicas.

## Run tests

```bash
source .venv/bin/activate
pytest detector/tests/ -v
```

## Run locally (without Docker)

Start Kafka however you like, then in separate terminals:

```bash
source .venv/bin/activate

# Terminal 1: generator
python -m generator.main --bootstrap-servers localhost:9092 --eps 50

# Terminal 2: detector
python -m detector.main --bootstrap-servers localhost:9092
```

## Verify

- Container health: `docker compose -f docker/docker-compose.yml ps`
- Kafka UI: [http://localhost:8080](http://localhost:8080)
- Generator logs: `docker compose -f docker/docker-compose.yml logs -f generator`
- Detector logs / alerts: `docker compose -f docker/docker-compose.yml logs -f detector`

## See it in action

After `docker compose up`, the generator starts producing events at 50/sec with a mix of normal users and three attacker profiles baked in. The detector picks these up and fires alerts as abuse thresholds are crossed.

**1. Watch alerts fire in real time:**

```bash
docker compose -f docker/docker-compose.yml logs -f detector 2>&1 | grep ALERT
```

You should see output like:

```
ALERT  rule=rate_abuse           severity=high     user=user_0009  events=62
ALERT  rule=prompt_injection     severity=critical  user=user_0010  events=5
ALERT  rule=token_abuse          severity=high     user=user_0011  events=6
```

Rate abuse fires first (~60s), then prompt injection (~minutes), then token abuse (~15min).

**2. Inspect topics in Kafka UI:**

Open [http://localhost:8080](http://localhost:8080) and check:
- `raw-api-events` — events flowing in across 3 partitions
- `alerts` — alert payloads produced by the detector, keyed by `user_id`

**3. Read raw alert payloads from the CLI:**

```bash
docker compose -f docker/docker-compose.yml exec kafka-1 \
  kafka-console-consumer --bootstrap-server localhost:9092 \
  --topic alerts --from-beginning
```

Each alert is a JSON object with `rule_id`, `severity`, `user_id`, `event_count`, and `window_seconds`.

## Stop

```bash
docker compose -f docker/docker-compose.yml down
```

Add `-v` to wipe all Kafka/ZooKeeper data for a clean restart.
