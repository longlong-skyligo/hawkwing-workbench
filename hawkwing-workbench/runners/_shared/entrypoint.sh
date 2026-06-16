#!/usr/bin/env bash
set -euo pipefail

INPUT_PATH="${1:-/out/input.json}"
OUT_DIR="${2:-/out}"
RUNNER_NAME="${RUNNER_NAME:-hawkwing-runner}"

mkdir -p "${OUT_DIR}/evidence/http" "${OUT_DIR}/evidence/screenshots" "${OUT_DIR}/evidence/files" "${OUT_DIR}/evidence/forensics" "${OUT_DIR}/evidence/pcap"

TARGET="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('target','unknown-target'))" "${INPUT_PATH}" 2>&1 || echo "unknown-target")"
JOB_ID="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('job_id','unknown-job'))" "${INPUT_PATH}" 2>&1 || echo "unknown-job")"
FINDING_ID="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('finding_id','unknown-finding'))" "${INPUT_PATH}" 2>&1 || echo "unknown-finding")"

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

# === Browser rendering via Playwright ===
BROWSER_DIR="${OUT_DIR}/evidence/browser"
mkdir -p "${BROWSER_DIR}"

if [[ "${TARGET}" =~ ^https?:// ]]; then
  echo "browser_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
  python3 - "${TARGET}" "${BROWSER_DIR}" <<'PY' >> "${OUT_DIR}/commands.log" 2>&1 || true
import sys
from pathlib import Path

target = sys.argv[1]
out_dir = Path(sys.argv[2])

try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        page = browser.new_page()
        page.goto(target, wait_until="networkidle", timeout=30000)
        print(f"browser_title={page.title()}")
        shot = out_dir / "page.png"
        page.screenshot(path=str(shot), full_page=True)
        print(f"browser_screenshot={shot}")
        html = page.content()
        (out_dir / "page.html").write_text(html, encoding="utf-8")
        print(f"browser_html_saved={out_dir / 'page.html'} ({len(html)} bytes)")
        browser.close()
except Exception as exc:
    print(f"browser_error={exc}")
PY
  echo "browser_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
fi

# === HTTP collection (raw evidence gathering, no flag extraction) ===
if [[ "${TARGET}" =~ ^https?:// ]]; then
  HTTP_DIR="${OUT_DIR}/evidence/http"
  PATHS=("/" "/robots.txt" "/flag" "/flag.txt" "/readme.txt" "/.well-known/security.txt")
  for path in "${PATHS[@]}"; do
    url="${TARGET%/}${path}"
    safe_name="$(echo "${path}" | sed 's#[/.]#_#g; s#^_$#index#')"
    echo "fetch=${url}" | tee -a "${OUT_DIR}/commands.log"
    curl -k -L --connect-timeout 8 --max-time 20 -A "HawkWing-Runner/0.1" \
      -D "${HTTP_DIR}/${safe_name}.headers.txt" \
      -o "${HTTP_DIR}/${safe_name}.body.txt" \
      "${url}" >/dev/null 2>&1 || true
  done
fi

# === Result: empty flag candidates, Runner AI will do the extraction ===
cat > "${OUT_DIR}/timeline.json" <<JSON
[
  {"event":"runner.started","runner":"${RUNNER_NAME}","target":"${TARGET}","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"},
  {"event":"runner.collection.completed","runner":"${RUNNER_NAME}","target":"${TARGET}","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
]
JSON

cat > "${OUT_DIR}/result.json" <<JSON
{
  "status": "completed",
  "runner": "${RUNNER_NAME}",
  "confidence": 0.5,
  "impact": "manual_review_required",
  "privilege_obtained": "none",
  "flag_candidates": [],
  "summary": "${RUNNER_NAME} collected evidence for ${TARGET}. Flag extraction delegated to Runner AI analysis engine.",
  "evidence_files": [
    "commands.log",
    "timeline.json",
    "evidence/http",
    "evidence/browser"
  ],
  "recommendation": "Raw evidence collected. Runner AI will perform multi-turn analysis to extract flag."
}
JSON

echo "completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
