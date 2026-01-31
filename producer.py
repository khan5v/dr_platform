from confluent_kafka import Producer
import json, time, random


def delivery_reporter(err, msg):
    if err is not None:
        print(f"Delivery failed for record {msg.key()}: {err}")
    else:
        print(
            f"Record {msg.key()} successfully produced to {msg.topic()} [{msg.partition()}] at offset {msg.offset()}"
        )


if __name__ == "__main__":
    producer = Producer(
        {
            "bootstrap.servers": "localhost:9092",
            "acks": "all",
            "client.id": "security-event-producer",
        }
    )

    for i in range(10000):
        event = {
            "timestamp": int(time.time()),
            "event_type": random.choice(
                ["login", "logout", "file_access", "network_connection"]
            ),
            "host": f"web-{random.randint(1, 5)}",
        }

        producer.produce(
            topic="security-events",
            key=str(event["host"]).encode("utf-8"),
            value=json.dumps(event),
            callback=delivery_reporter,
        )

        producer.poll(0)
        if i % 50 == 0:
            print("Produced 50 messages")

    producer.flush()
