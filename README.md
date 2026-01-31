# DR Platform

A real-time abuse detection platform — streaming telemetry through Kafka into detection, alerting, and investigation layers.

## Vision

Build a full detection & response pipeline that ingests API events, enriches and normalizes them, runs windowed detection rules (rate abuse, prompt injection, token stuffing), routes alerts by severity, and provides dashboards and investigation tooling. The platform progresses through phases:

## What's here so far

- 3-broker Kafka cluster (Confluent CP 7.6.0) with ZooKeeper
- Kafka UI for topic/consumer group inspection

## Setup

```bash
chmod +x setup.sh
./setup.sh
```

This installs Python deps (`confluent-kafka`, `protobuf`), pulls Docker images, and sets up a virtualenv.

## Run

```bash
docker compose up -d
```

## Verify

- Check container health: `docker compose ps`
- Kafka UI: [http://localhost:8080](http://localhost:8080)
- Brokers are available on `localhost:9092`, `localhost:9093`, `localhost:9094`
