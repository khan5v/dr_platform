# DR Platform

Real-time Claude API abuse detection platform — streaming telemetry through Kafka into detection, alerting, and investigation layers.

## What's here

- 3-broker Kafka cluster (Confluent CP 7.6.0) with ZooKeeper
- Kafka UI for topic/consumer group inspection
- Event generator (`producer.py`) — simulates Claude API telemetry with configurable normal and abusive user profiles

## Setup

```bash
chmod +x setup.sh
./setup.sh
```

Installs Python deps (`confluent-kafka`, `protobuf`), pulls Docker images, and sets up a virtualenv.

## Run

```bash
docker compose -f docker/docker-compose.yml up -d
```

This starts ZooKeeper, 3 Kafka brokers, Kafka UI, and the event generator.

## Generator configuration

The generator runs inside Docker with defaults (8 normal users, 1 rate abuser, 1 prompt injector, 1 token abuser, 50 events/sec). To customize, edit the `command` in `docker/docker-compose.yml` or run locally:

```bash
source .venv/bin/activate
python producer.py --normal 20 --rate-abusers 2 --injection-abusers 2 --token-abusers 1 --eps 100
```

## Stop

```bash
docker compose -f docker/docker-compose.yml down
```

## Clean restart (wipes all Kafka/ZooKeeper data)

```bash
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d
```

The `-v` flag removes volumes. Use this if brokers fail to start with `NodeExistsException` or you want a fresh topic state.

## Rebuild after code changes

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

## Verify

- Container health: `docker compose -f docker/docker-compose.yml ps`
- Kafka UI: [http://localhost:8080](http://localhost:8080)
- Generator logs: `docker compose -f docker/docker-compose.yml logs -f generator`
- Brokers: `localhost:9092`, `localhost:9093`, `localhost:9094`
