"""Detection consumer — reads raw events, runs the engine, produces alerts.

Consumes from raw-api-events, evaluates each event against all detection
rules, and publishes any alerts to the alerts topic.  One consumer instance
per partition (scaled via consumer group + docker-compose replicas).

Usage:
    python -m detector.main
    python -m detector.main --bootstrap-servers kafka-1:29092 --input-topic raw-api-events
"""

import argparse
import json
import signal
import sys

from confluent_kafka import Consumer, Producer, KafkaError
from confluent_kafka.admin import AdminClient, NewTopic

from detector.engine import DetectionEngine

running = True


def _shutdown(sig, frame):
    global running
    print("\nShutting down consumer...")
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


def main():
    parser = argparse.ArgumentParser(description="Detection consumer")
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--input-topic", default="raw-api-events")
    parser.add_argument("--output-topic", default="alerts")
    parser.add_argument("--group-id", default="detection-engine")
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

    engine = DetectionEngine()
    consumed = 0
    alerts_produced = 0

    print(f"Detection consumer started  input={args.input_topic}  "
          f"output={args.output_topic}  rules={len(engine.rules)}")

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

            event = json.loads(msg.value().decode("utf-8"))
            consumed += 1

            alerts = engine.evaluate(event)
            for alert in alerts:
                producer.produce(
                    args.output_topic,
                    key=alert["user_id"],
                    value=json.dumps(alert).encode("utf-8"),
                )
                alerts_produced += 1
                print(f"ALERT  rule={alert['rule_id']:<20s} "
                      f"severity={alert['severity']:<8s} "
                      f"user={alert['user_id']}  events={alert['event_count']}")

            # Batch flush every 1000 events (producer buffers internally)
            if consumed % 1000 == 0:
                producer.flush()

            if consumed % 500 == 0:
                print(f"  ... {consumed} events consumed, {alerts_produced} alerts produced")
    finally:
        producer.flush()
        consumer.close()
        print(f"Done. {consumed} events consumed, {alerts_produced} alerts produced.")


if __name__ == "__main__":
    main()
