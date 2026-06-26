#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [ ! -f .env ]; then
  echo "Creating .env from .env.example..."
  cp .env.example .env
  # Generate a random secret key
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/change-me-to-a-long-random-string/$SECRET/" .env
  echo ".env created. Review and edit it before running in production."
fi

echo "Starting SOCINT..."
docker compose up -d

echo ""
echo "Services starting:"
echo "  Frontend:    http://localhost:3000"
echo "  API:         http://localhost:8000/api/docs"
echo "  OpenSearch:  http://localhost:9200"
echo "  RabbitMQ:    http://localhost:15672  (socint/socint)"
echo "  MinIO:       http://localhost:9001   (socint/socint123)"
echo ""
echo "Run 'docker compose logs -f' to watch logs."
