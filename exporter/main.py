"""Prometheus metrics exporter — consumes Kafka events and exposes metrics.

Subscribes to both raw-api-events and alerts topics, updating Prometheus
counters, histograms, and gauges in real-time.  Grafana reads from Prometheus
to render the security operations dashboard.

Usage:
    python -m exporter.main
    python -m exporter.main --bootstrap-servers kafka-1:29092 --port 9090
"""

import argparse
import json
import signal
import sys
import time

from confluent_kafka import Consumer, KafkaError
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# ---------------------------------------------------------------------------
# Event metrics
# ---------------------------------------------------------------------------
# Each Counter/Histogram/Gauge below auto-registers itself in a global
# REGISTRY on construction.  No manual wiring needed — start_http_server()
# iterates that registry on every GET /metrics and serialises all values
# into the Prometheus text exposition format.
events_total = Counter(
    "dr_events_total",
    "Total events processed",
    ["event_type"],
)
events_by_user = Counter(
    "dr_events_by_user_total",
    "Events by user and type",
    ["user_id", "event_type"],
)
events_by_model = Counter(
    "dr_events_by_model_total",
    "Events by model",
    ["model"],
)

# ---------------------------------------------------------------------------
# Alert metrics
# ---------------------------------------------------------------------------
alerts_total = Counter(
    "dr_alerts_total",
    "Total detection alerts",
    ["rule_id", "severity"],
)
alerts_by_user = Counter(
    "dr_alerts_by_user_total",
    "Alerts per user per rule",
    ["user_id", "rule_id"],
)

# ---------------------------------------------------------------------------
# Safety metrics
# ---------------------------------------------------------------------------
safety_triggers_total = Counter(
    "dr_safety_triggers_total",
    "Safety trigger events by type",
    ["trigger_type"],
)

# ---------------------------------------------------------------------------
# Token metrics
# ---------------------------------------------------------------------------
input_tokens_total = Counter(
    "dr_input_tokens_total",
    "Total input tokens consumed",
)
output_tokens_total = Counter(
    "dr_output_tokens_total",
    "Total output tokens produced",
)
cache_read_tokens_total = Counter(
    "dr_cache_read_tokens_total",
    "Total tokens served from cache",
)

# ---------------------------------------------------------------------------
# Latency & token distribution
# ---------------------------------------------------------------------------
# Histograms partition .observe() values into cumulative buckets, so
# Prometheus can compute quantiles (p50/p95/p99) without storing every
# data point — a fixed-memory trade-off vs. full distribution tracking.
request_latency = Histogram(
    "dr_request_latency_milliseconds",
    "API request latency distribution",
    buckets=[50, 100, 200, 500, 1000, 2000, 5000, 10000],
)
input_tokens_per_request = Histogram(
    "dr_input_tokens_per_request",
    "Input tokens per request distribution",
    buckets=[100, 500, 1000, 5000, 10000, 50000, 100000, 150000, 200000],
)

# ---------------------------------------------------------------------------
# Throughput gauge (updated every second)
# ---------------------------------------------------------------------------
events_per_second = Gauge(
    "dr_events_per_second",
    "Current event processing rate",
)
export_errors_total = Counter(
    "dr_export_errors_total",
    "JSON parse or Kafka consumer errors in the exporter",
)

running = True


def _shutdown(sig, frame):
    global running
    print("\nShutting down exporter...")
    running = False


signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# ---------------------------------------------------------------------------
# Metric updaters
# ---------------------------------------------------------------------------

def _process_raw_event(event: dict):
    """Update Prometheus metrics for a raw API event."""
    event_type = event.get("event_type", "unknown")
    user_id = event.get("user_id", "unknown")

    events_total.labels(event_type=event_type).inc()
    events_by_user.labels(user_id=user_id, event_type=event_type).inc()

    if event_type == "api_request":
        model = event.get("model", "unknown")
        events_by_model.labels(model=model).inc()

        input_tok = event.get("input_tokens", 0)
        output_tok = event.get("output_tokens", 0)
        cache_read = event.get("cache_read_input_tokens", 0)
        latency = event.get("latency_ms", 0)

        input_tokens_total.inc(input_tok)
        output_tokens_total.inc(output_tok)
        cache_read_tokens_total.inc(cache_read)
        request_latency.observe(latency)
        input_tokens_per_request.observe(input_tok)

    elif event_type == "safety_trigger":
        trigger_type = event.get("trigger_type", "unknown")
        safety_triggers_total.labels(trigger_type=trigger_type).inc()

    # rate_limit_event — counted via events_total, no extra metrics needed


def _process_alert(alert: dict):
    """Update Prometheus metrics for a detection alert."""
    rule_id = alert.get("rule_id", "unknown")
    severity = alert.get("severity", "unknown")
    user_id = alert.get("user_id", "unknown")

    alerts_total.labels(rule_id=rule_id, severity=severity).inc()
    alerts_by_user.labels(user_id=user_id, rule_id=rule_id).inc()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Prometheus metrics exporter")
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument(
        "--port", type=int, default=9090, help="Prometheus metrics HTTP port",
    )
    args = parser.parse_args()

    # Spins up a daemon thread running an HTTP server (stdlib http.server).
    # Serves /metrics with every Counter, Histogram, and Gauge defined above —
    # no routes, no framework, just the prometheus_client global registry.
    start_http_server(args.port)
    print(f"Prometheus metrics server started on :{args.port}")

    consumer = Consumer({
        "bootstrap.servers": args.bootstrap_servers,
        "group.id": "metrics-exporter",
        "auto.offset.reset": "latest",
        "enable.auto.commit": True,
    })
    consumer.subscribe(["raw-api-events", "alerts"])

    count = 0
    window_start = time.time()
    window_count = 0

    print("Exporter consuming from raw-api-events + alerts ...")

    try:
        while running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                export_errors_total.inc()
                print(f"Consumer error: {msg.error()}", file=sys.stderr)
                continue

            try:
                data = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                export_errors_total.inc()
                continue

            topic = msg.topic()

            if topic == "raw-api-events":
                _process_raw_event(data)
            elif topic == "alerts":
                _process_alert(data)

            count += 1
            window_count += 1

            # Update EPS gauge roughly every second
            now = time.time()
            elapsed = now - window_start
            if elapsed >= 1.0:
                events_per_second.set(window_count / elapsed)
                window_start = now
                window_count = 0

            if count % 5000 == 0:
                print(f"  ... {count} messages exported to metrics")
    finally:
        consumer.close()
        print(f"Exporter done. {count} messages processed.")


if __name__ == "__main__":
    main()
