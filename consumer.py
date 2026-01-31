"""Simple consumer for verifying events in a consumer group.

Usage:
    python consumer.py
    python consumer.py --bootstrap-servers kafka-1:29092 --topic raw-api-events
"""

import argparse
import json
import signal

from confluent_kafka import Consumer

running = True


def _shutdown(sig, frame):
    global running
    print("\nShutting down consumer...")
    running = False


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


def main():
    parser = argparse.ArgumentParser(description="Event consumer")
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--topic", default="raw-api-events")
    parser.add_argument("--group-id", default="security-processor")
    args = parser.parse_args()

    consumer = Consumer({
        "bootstrap.servers": args.bootstrap_servers,
        "group.id": args.group_id,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([args.topic])

    count = 0
    try:
        while running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print(f"Consumer error: {msg.error()}")
                continue

            event = json.loads(msg.value().decode("utf-8"))
            count += 1
            print(f"[partition={msg.partition()}] {event['event_type']:<20s} "
                  f"user={event['user_id']}  org={event['org_id']}")

            if count % 500 == 0:
                print(f"  ... {count} events consumed")
    finally:
        consumer.close()
        print(f"Done. {count} events consumed.")


if __name__ == "__main__":
    main()
