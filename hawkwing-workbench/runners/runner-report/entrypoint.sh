#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-/out/report.md}"
OUTPUT="${2:-/out/report.html}"

if [ -f "${INPUT}" ]; then
  pandoc "${INPUT}" -o "${OUTPUT}"
  echo "Report exported to ${OUTPUT}"
else
  echo "Input report not found: ${INPUT}" >&2
  exit 1
fi

