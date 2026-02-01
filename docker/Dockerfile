# Shared image for all Python services (generator, detector).
# Each service uses the same image; docker-compose `command` selects the module.

FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies first (cached layer — changes infrequently)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (changes frequently)
COPY generator/ generator/
COPY detector/ detector/
