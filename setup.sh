#!/usr/bin/env bash
set -euo pipefail

# --- Pre-flight checks ---

echo "=== Checking prerequisites ==="

if ! command -v docker &>/dev/null; then
  echo "ERROR: docker is not installed. Install Docker Desktop first."
  exit 1
fi
echo "docker: $(docker --version)"

if ! docker compose version &>/dev/null; then
  echo "ERROR: 'docker compose' plugin not found. Update Docker Desktop or install the compose plugin."
  exit 1
fi
echo "compose: $(docker compose version)"

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3.12+."
  exit 1
fi
echo "python:  $(python3 --version)"

# --- venv ---

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  echo "Created virtualenv at .venv"
else
  echo "Virtualenv .venv already exists, skipping creation"
fi

source .venv/bin/activate

# --- System dependencies for confluent-kafka (C extension) ---

echo ""
echo "=== Installing system dependencies ==="

if [[ "$(uname)" == "Darwin" ]]; then
  if command -v brew &>/dev/null; then
    if ! brew list librdkafka &>/dev/null 2>&1; then
      echo "Installing librdkafka via Homebrew (required by confluent-kafka on macOS)..."
      brew install librdkafka
    else
      echo "librdkafka already installed"
    fi
  else
    echo "WARNING: Homebrew not found. If confluent-kafka fails to install, run: brew install librdkafka"
  fi
elif [[ "$(uname)" == "Linux" ]]; then
  if command -v apt-get &>/dev/null; then
    if ! dpkg -s librdkafka-dev &>/dev/null 2>&1; then
      echo "Installing librdkafka-dev via apt (required by confluent-kafka on Linux)..."
      sudo apt-get update -qq && sudo apt-get install -y -qq librdkafka-dev
    else
      echo "librdkafka-dev already installed"
    fi
  elif command -v dnf &>/dev/null; then
    if ! rpm -q librdkafka-devel &>/dev/null 2>&1; then
      echo "Installing librdkafka-devel via dnf..."
      sudo dnf install -y librdkafka-devel
    else
      echo "librdkafka-devel already installed"
    fi
  else
    echo "WARNING: Could not detect package manager. If confluent-kafka fails, install librdkafka manually."
  fi
fi

# --- Python dependencies ---

echo ""
echo "=== Installing Python packages ==="

pip install --quiet --upgrade pip
pip install --quiet -r requirements-dev.txt

echo "Verifying confluent-kafka..."
python3 -c "import confluent_kafka; print(f'  confluent-kafka {confluent_kafka.version()}')"

echo "Verifying protobuf..."
python3 -c "import google.protobuf; print(f'  protobuf {google.protobuf.__version__}')"

echo "Verifying pytest..."
python3 -c "import pytest; print(f'  pytest {pytest.__version__}')"

# --- Docker images ---

echo ""
echo "=== Pulling Docker images ==="

docker pull confluentinc/cp-kafka:7.6.0
docker pull confluentinc/cp-zookeeper:7.6.0
docker pull provectuslabs/kafka-ui:latest

# --- kcat (optional) ---

echo ""
echo "=== Installing kcat (optional) ==="

if command -v kcat &>/dev/null; then
  echo "kcat already installed: $(kcat -V 2>&1 | head -1)"
elif [[ "$(uname)" == "Darwin" ]] && command -v brew &>/dev/null; then
  brew install kcat
elif command -v apt-get &>/dev/null; then
  sudo apt-get install -y -qq kafkacat
elif command -v dnf &>/dev/null; then
  sudo dnf install -y kafkacat
else
  echo "SKIP: Could not auto-install kcat. Install it manually for ad-hoc Kafka CLI testing."
fi

# --- Done ---

echo ""
echo "=== Setup complete ==="
echo "To activate the virtualenv in a new shell:"
echo "  source .venv/bin/activate"
echo ""
echo "Run tests:   pytest detector/tests/ -v"
echo "Run Docker:  docker compose -f docker/docker-compose.yml up -d --build"
