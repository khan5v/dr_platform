# Shared image for all Python services (generator, detector, triage).
# Each service uses the same image; docker-compose `command` selects the script.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir confluent-kafka
# Build context is project root (context: .. in docker-compose.yml),
# so this copies producer.py, detector.py, rules/, etc. into /app
COPY . .
