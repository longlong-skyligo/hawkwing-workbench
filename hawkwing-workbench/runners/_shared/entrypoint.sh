#!/usr/bin/env bash
set -euo pipefail

INPUT_PATH="${1:-/out/input.json}"
OUT_DIR="${2:-/out}"
RUNNER_NAME="${RUNNER_NAME:-hawkwing-runner}"

mkdir -p "${OUT_DIR}/evidence/http" "${OUT_DIR}/evidence/screenshots" "${OUT_DIR}/evidence/files" "${OUT_DIR}/evidence/forensics" "${OUT_DIR}/evidence/pcap"

TARGET="$(jq -r '.target // "unknown-target"' "${INPUT_PATH}" 2>/dev/null || echo "unknown-target")"
JOB_ID="$(jq -r '.job_id // "unknown-job"' "${INPUT_PATH}" 2>/dev/null || echo "unknown-job")"
FINDING_ID="$(jq -r '.finding_id // "unknown-finding"' "${INPUT_PATH}" 2>/dev/null || echo "unknown-finding")"

{
  echo "runner=${RUNNER_NAME}"
  echo "job_id=${JOB_ID}"
  echo "finding_id=${FINDING_ID}"
  echo "target=${TARGET}"
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "available_tools:"
  for tool in nmap naabu httpx subfinder nuclei ffuf katana tshark zeek suricata impacket-GetADUsers bloodhound-python volatility3 binwalk gdb r2 trivy; do
    if command -v "${tool}" >/dev/null 2>&1; then
      echo "  - ${tool}: $(command -v "${tool}")"
    fi
  done
} | tee "${OUT_DIR}/commands.log"

cat > "${OUT_DIR}/timeline.json" <<JSON
[
  {"event":"runner.started","runner":"${RUNNER_NAME}","target":"${TARGET}","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"},
  {"event":"runner.placeholder.completed","runner":"${RUNNER_NAME}","target":"${TARGET}","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
]
JSON

cat > "${OUT_DIR}/result.json" <<JSON
{
  "status": "completed",
  "runner": "${RUNNER_NAME}",
  "confidence": 0.7,
  "impact": "manual_review_required",
  "privilege_obtained": "none",
  "summary": "${RUNNER_NAME} completed baseline controlled task for ${TARGET}. Replace or extend the runner command workflow for live competitions.",
  "evidence_files": [
    "commands.log",
    "timeline.json"
  ],
  "recommendation": "Review generated evidence and use approved runbooks for deeper validation."
}
JSON

echo "completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"

