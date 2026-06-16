"""Headless browser service for main AI framework.

Provides Playwright-based page capture that the intake planner
and main AI can use to inspect target web pages before
generating the execution plan.
"""

import json
from pathlib import Path
from typing import Any

from app.config import get_settings


def capture_target_page(target: str) -> dict[str, Any]:
    """Capture a target URL with headless Chromium.

    Returns:
        dict with keys: title, body_text, screenshot_path, page_html, error
    """
    result: dict[str, Any] = {
        "title": "",
        "body_text": "",
        "screenshot_path": "",
        "page_html": "",
        "flags_found": [],
        "error": None,
    }

    settings = get_settings()
    capture_dir = Path(settings.workspace_root) / "_browser-captures"
    capture_dir.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
            )
            page = browser.new_page()
            page.goto(target, wait_until="networkidle", timeout=30000)

            result["title"] = page.title()
            result["body_text"] = page.inner_text("body")[:10000]
            result["page_html"] = page.content()[:30000]

            # Screenshot
            import hashlib
            safe_name = hashlib.md5(target.encode()).hexdigest()[:12]
            shot_path = capture_dir / f"{safe_name}.png"
            page.screenshot(path=str(shot_path), full_page=True)
            result["screenshot_path"] = str(shot_path)

            # Flag search in DOM
            import re
            patterns = [
                r"flag\{[^}\r\n]{1,200}\}",
                r"ctfshow\{[^}\r\n]{1,200}\}",
                r"ctf\{[^}\r\n]{1,200}\}",
                r"FLAG\{[^}\r\n]{1,200}\}",
            ]
            html = result["page_html"]
            for pat in patterns:
                for m in re.finditer(pat, html, re.IGNORECASE):
                    result["flags_found"].append({
                        "candidate": m.group(0),
                        "source": "browser-dom",
                    })

            browser.close()

    except ImportError:
        result["error"] = "playwright not installed"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def capture_page_summary(target: str) -> str:
    """Capture target page and return a markdown summary for the AI prompt."""
    data = capture_target_page(target)
    if data.get("error"):
        return f"(Browser capture failed: {data['error']})"

    parts = [
        f"### Browser Capture: {target}",
        f"**Page Title**: {data['title']}",
        f"**Body Text (first 4k chars)**:",
        f"```",
        data["body_text"][:4000],
        f"```",
    ]
    if data["flags_found"]:
        parts.append(f"**Browser-found flag candidates**: {json.dumps(data['flags_found'], ensure_ascii=False)}")
    return "\n".join(parts)
