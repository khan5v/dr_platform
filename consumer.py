from confluent_kafka import Consumer
import json

if __name__ == "__main__":
    consumer = Consumer(
        {
            "bootstrap.servers": "localhost:9092",
            "group.id": "security-processor",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
        }
    )

    consumer.subscribe(["raw-api-events"])

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print(f"Consumer error: {msg.error()}")
                continue

            event = json.loads(msg.value().decode("utf-8"))
            print(f"Consumed event: {event}")

    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()