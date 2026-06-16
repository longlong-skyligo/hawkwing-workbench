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
BROWSER_FLAGS="[]"

if [[ "${TARGET}" =~ ^https?:// ]]; then
  echo "browser_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
  BROWSER_FLAGS="$(python3 - "${TARGET}" "${BROWSER_DIR}" <<'PY'
import sys, json
from pathlib import Path

target = sys.argv[1]
out_dir = Path(sys.argv[2])
result = {"screenshot": None, "title": "", "body_text": "", "flags_found": []}

try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        page = browser.new_page()
        page.goto(target, wait_until="networkidle", timeout=30000)
        result["title"] = page.title()
        result["body_text"] = page.inner_text("body")[:8000]
        # Screenshot
        shot = out_dir / "page.png"
        page.screenshot(path=str(shot), full_page=True)
        result["screenshot"] = str(shot)
        # DOM source
        html = page.content()
        (out_dir / "page.html").write_text(html, encoding="utf-8")
        # Search for flags in rendered DOM
        import re
        patterns = [
            r"flag\{[^}\r\n]{1,200}\}",
            r"ctfshow\{[^}\r\n]{1,200}\}",
            r"ctf\{[^}\r\n]{1,200}\}",
            r"FLAG\{[^}\r\n]{1,200}\}",
        ]
        for pat in patterns:
            for m in re.finditer(pat, html, re.IGNORECASE):
                result["flags_found"].append({"candidate": m.group(0), "source": "playwright-dom"})
        browser.close()
except Exception as exc:
    result["error"] = str(exc)

print(json.dumps(result, ensure_ascii=False))
PY
)"
  echo "browser_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
fi

FLAG_CANDIDATES_JSON="[]"
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
  FLAG_CANDIDATES_JSON="$(python3 - "${HTTP_DIR}" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
patterns = [
    r"flag\{[^}\r\n]{1,200}\}",
    r"ctfshow\{[^}\r\n]{1,200}\}",
    r"FLAG\{[^}\r\n]{1,200}\}",
    r"flag\s*[:=]\s*['\"]?([A-Za-z0-9_@{}./:\-]{6,200})",
]
seen = set()
found = []
for path in root.rglob("*.txt"):
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(1) if match.lastindex else match.group(0)
            if value not in seen:
                seen.add(value)
                found.append({"candidate": value, "source": str(path.name)})
print(json.dumps(found, ensure_ascii=False))
PY
)"
fi

cat > "${OUT_DIR}/timeline.json" <<JSON
[
  {"event":"runner.started","runner":"${RUNNER_NAME}","target":"${TARGET}","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"},
  {"event":"runner.placeholder.completed","runner":"${RUNNER_NAME}","target":"${TARGET}","time":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
]
JSON

# Merge browser flags into curl flags
MERGED_FLAGS="$(python3 -c "
import json
curl = json.loads('''${FLAG_CANDIDATES_JSON}''')
browser_data = json.loads('''${BROWSER_FLAGS}''')
browser = browser_data.get('flags_found', []) if isinstance(browser_data, dict) else []
seen = {c['candidate'] for c in curl}
for b in browser:
    if b['candidate'] not in seen:
        curl.append(b)
        seen.add(b['candidate'])
print(json.dumps(curl, ensure_ascii=False))
" 2>/dev/null || echo "${FLAG_CANDIDATES_JSON}")"

cat > "${OUT_DIR}/result.json" <<JSON
{
  "status": "completed",
  "runner": "${RUNNER_NAME}",
  "confidence": 0.7,
  "impact": "manual_review_required",
  "privilege_obtained": "none",
  "flag_candidates": ${MERGED_FLAGS},
  "summary": "${RUNNER_NAME} completed controlled validation for ${TARGET}. Flag candidates: ${MERGED_FLAGS}.",
  "evidence_files": [
    "commands.log",
    "timeline.json",
    "evidence/http",
    "evidence/browser"
  ],
  "recommendation": "Review flag candidates first. If no flag was found, inspect HTTP evidence, browser screenshot, and AI analysis for the next focused check."
}
JSON

echo "completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
