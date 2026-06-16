#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}/deploy"

if [ ! -f .env ]; then
  cp .env.example .env
fi

docker compose --profile build-runners build

