# DR Platform

A real-time abuse detection platform — streaming telemetry through Kafka into detection, alerting, and investigation layers.

## Vision

Build a full detection & response pipeline that ingests API events, enriches and normalizes them, runs windowed detection rules (rate abuse, prompt injection, token stuffing), routes alerts by severity, and provides dashboards and investigation tooling. The platform progresses through phases:

## What's here so far

- 3-broker Kafka cluster (Confluent CP 7.6.0) with ZooKeeper
- Kafka UI for topic/consumer group inspection
- Simple producer (`producer.py`) that sends randomized security events (login, logout, file_access, network_connection) to the `security-events` topic
- Simple consumer (`consumer.py`) that reads from the `security-events` topic and prints events to stdout

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

## Create the topic

Via CLI:

```bash
docker exec dr_platform-kafka-1-1 kafka-topics --create --topic security-events --partitions 3 --replication-factor 3 --bootstrap-server localhost:29092
```

Or create it manually through Kafka UI at [http://localhost:8080](http://localhost:8080).

## Produce test events

```bash
source .venv/bin/activate
python producer.py
```

This sends 10k sample security events into the `security-events` topic.

## Consume events

In a separate terminal:

```bash
source .venv/bin/activate
python consumer.py
```

This joins the `security-processor` consumer group, reads from the `security-events` topic (starting from the earliest offset), and prints each event to the console. Stop it with `Ctrl+C`.

## Verify

- Check container health: `docker compose ps`
- Kafka UI: [http://localhost:8080](http://localhost:8080)
- Brokers are available on `localhost:9092`, `localhost:9093`, `localhost:9094`
