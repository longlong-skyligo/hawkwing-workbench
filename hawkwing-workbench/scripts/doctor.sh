#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "[1/4] Python syntax check"
python -m py_compile \
  apps/api/app/main.py \
  apps/api/app/models.py \
  apps/api/app/schemas.py \
  apps/api/app/services/catalog.py \
  apps/api/app/services/evidence.py \
  apps/api/app/services/execution_planner.py \
  apps/api/app/services/dynamic_builder.py \
  apps/api/app/services/state_bus.py \
  apps/api/app/workers/tasks.py

echo "[2/4] YAML parse check"
python - <<'PY'
import pathlib
import yaml

for path in pathlib.Path("config").glob("*.yaml"):
    yaml.safe_load(path.read_text(encoding="utf-8"))
print("yaml ok")
PY

echo "[3/4] Compose config check"
cd deploy
if [ ! -f .env ]; then
  cp .env.example .env
fi
docker compose config >/dev/null

echo "[4/4] Done"

