#!/usr/bin/env python3
"""Playwright walkthrough of the androsec Flask UI → numbered screenshots."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
SHOT_DIR = DEMO_DIR / "screenshots"
DEFAULT_BASE = "http://127.0.0.1:5000"
# Enough tools that /scan stays visible long enough for a screenshot.
DEFAULT_ANALYZERS = [
    "apk_info",
    "manifest",
    "permission",
    "component",
    "secret_detector",
    "static_code",
    "storage",
    "network",
]
DEFAULT_APK = "root:DivaApplication.apk"

# Step catalog used by generate_report.py (id → copy). Screenshots may be
# skipped when a page is unreachable; the report notes gaps from notes[].
STEP_COPY = {
    "01-home": {
        "title": "Home",
        "route": "/",
        "summary": "Landing page for the androsec assessment workspace.",
        "detail": (
            "Introduces the King Saud University graduation project: local APK "
            "assessment with static and dynamic analyzers, MASVS-mapped reports, "
            "and AI-assisted exploitation that stays on this machine. From here "
            "the user starts an assessment or reviews what the framework can run."
        ),
    },
    "02-assessment": {
        "title": "Assessment — choose an APK",
        "route": "/assess",
        "summary": "Upload or select a lab APK, then analyze or decompile.",
        "detail": (
            "The Assessment library lists sample APKs shipped with the repo "
            "(DIVA, InsecureBankv2, UnCrackable, …) plus any uploads. Users pick "
            "a target, then continue to analyzer selection or start a decompile."
        ),
    },
    "03-analyzers": {
        "title": "Analyzer selection",
        "route": "/assess/analyzers",
        "summary": "Choose static and optional dynamic tools before the scan.",
        "detail": (
            "Static analyzers are selected by default. Dynamic checks stay off "
            "until the user enables them and authorizes a connected device. "
            "Bulk controls (select static / all / clear) speed up configuration."
        ),
    },
    "04-scanning": {
        "title": "Scan progress",
        "route": "/scan/<job_id>",
        "summary": "Live progress while each analyzer runs against the APK.",
        "detail": (
            "The scanning board shows percent complete, elapsed time, and a "
            "per-tool checklist. When the job finishes, the UI navigates to the "
            "HTML security report for that run."
        ),
    },
    "05-report": {
        "title": "Security report",
        "route": "/reports/<filename>",
        "summary": "Evidence-backed HTML report with PDF download.",
        "detail": (
            "The report summarizes findings, severity, and MASVS mapping. A "
            "sticky bar offers PDF download. Individual findings can open the "
            "AI Exploit workflow with the finding payload and scan metadata."
        ),
    },
    "06-device": {
        "title": "Device readiness",
        "route": "/device",
        "summary": "Connect and authorize a phone or emulator for dynamic checks.",
        "detail": (
            "Dynamic analyzers require adb on PATH and a ready serial. The page "
            "lists connected devices, supports TCP/IP connect, install/root "
            "helpers, and blocks dynamic scans until authorization is confirmed."
        ),
    },
    "07-exploit": {
        "title": "AI exploit & evidence",
        "route": "/exploit",
        "summary": "Grounded PoC planning for a single finding (BYOK).",
        "detail": (
            "Opened from a live report finding. The operator pastes an API key "
            "(used only for that request), acknowledges lab responsibility, and "
            "runs a grounded ADB/Frida PoC pipeline with an evidence gate and "
            "optional exploitation PDF."
        ),
    },
    "08-decompile": {
        "title": "Decompile workspace",
        "route": "/decompile/<job_id>",
        "summary": "apktool + jadx decode, browse, and rebuild.",
        "detail": (
            "Started from Assessment. While decoding, the page shows live status; "
            "when done, users browse resources or Java sources and can rebuild "
            "the APK from the apktool project."
        ),
    },
}


def wait_healthy(base: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base.rstrip("/") + "/", timeout=3) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
        time.sleep(0.75)
    raise SystemExit(f"Web UI not reachable at {base} ({last_err})")


def shot(page, name: str, notes: list[str] | None = None) -> dict:
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    path = SHOT_DIR / f"{name}.png"
    page.screenshot(path=str(path), full_page=True)
    meta = dict(STEP_COPY.get(name, {"title": name, "route": page.url, "summary": "", "detail": ""}))
    meta.update(
        {
            "id": name,
            "file": path.name,
            "url": page.url,
            "notes": notes or [],
            "captured": True,
        }
    )
    print(f"  saved {path.name}  ({page.url})")
    return meta


def stub(name: str, reason: str) -> dict:
    meta = dict(STEP_COPY.get(name, {"title": name, "route": "", "summary": "", "detail": ""}))
    meta.update(
        {
            "id": name,
            "file": None,
            "url": None,
            "notes": [reason],
            "captured": False,
        }
    )
    print(f"  skip  {name}: {reason}")
    return meta


def pick_apk_key(page, preferred: str) -> str | None:
    radios = page.locator('input[type="radio"][name="apk"]')
    count = radios.count()
    if count == 0:
        return None
    values = [radios.nth(i).get_attribute("value") or "" for i in range(count)]
    if preferred in values:
        page.locator(f'input[type="radio"][name="apk"][value="{preferred}"]').check()
        return preferred
    # Prefer a root sample named Diva if present
    for value in values:
        if value.endswith("DivaApplication.apk"):
            page.locator(f'input[type="radio"][name="apk"][value="{value}"]').check()
            return value
    radios.first.check()
    return values[0]


def configure_analyzers(page, analyzers: list[str]) -> None:
    page.evaluate(
        """(ids) => {
          document.querySelectorAll('input[name="analyzers"]').forEach((box) => {
            box.checked = ids.includes(box.value);
          });
        }""",
        analyzers,
    )


def wait_scan_done(page, timeout_ms: int = 300_000) -> bool:
    """Poll until status title says complete or URL moves to /reports/."""
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        url = page.url
        if "/reports/" in url:
            return True
        try:
            title = page.locator("#status-title").inner_text(timeout=1000)
        except Exception:
            title = ""
        if re.search(r"complete|done|finished|report", title, re.I):
            # scanning.html redirects via JS; give it a moment
            page.wait_for_timeout(1500)
            if "/reports/" in page.url:
                return True
        # Also poll status API if we can parse job id
        m = re.search(r"/scan/([a-f0-9]+)", url)
        if m:
            try:
                with urllib.request.urlopen(
                    url.split("/scan/")[0] + f"/scan/{m.group(1)}/status", timeout=5
                ) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") == "done":
                        page.goto(
                            url.split("/scan/")[0] + f"/report/{m.group(1)}",
                            wait_until="domcontentloaded",
                            timeout=60_000,
                        )
                        return True
                    if data.get("status") == "error":
                        print(f"  scan error: {data.get('error') or data.get('message')}")
                        return False
            except Exception:
                pass
        page.wait_for_timeout(1500)
    return False


def run(base: str, apk: str, analyzers: list[str], do_scan: bool, headed: bool) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Install demo deps: pip install -r requirements.txt && playwright install chromium")
        return 1

    wait_healthy(base)
    base = base.rstrip("/")
    steps: list[dict] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=1.5,
        )
        page = context.new_page()
        page.set_default_timeout(45_000)

        # 01 Home
        page.goto(f"{base}/", wait_until="networkidle")
        page.wait_for_selector("section.hero, .brand")
        steps.append(shot(page, "01-home"))

        # 02 Assessment
        page.goto(f"{base}/assess", wait_until="networkidle")
        page.wait_for_selector("header.page-head, #upload-form, .empty")
        apk_key = pick_apk_key(page, apk)
        assess_notes: list[str] = []
        if not apk_key:
            assess_notes.append(
                "No APK in the Assessment library — captured upload/empty UI. "
                "Place a sample .apk in the repo root or upload one to continue past this step."
            )
        else:
            assess_notes.append(f"Selected APK key: {apk_key}")
        steps.append(shot(page, "02-assessment", assess_notes))

        # 03 Analyzers
        if apk_key:
            page.goto(f"{base}/assess/analyzers?apk={apk_key}", wait_until="networkidle")
            page.wait_for_selector("#scan-form, .tool-grid")
            configure_analyzers(page, analyzers)
            steps.append(
                shot(
                    page,
                    "03-analyzers",
                    [f"Demo scan analyzers: {', '.join(analyzers)}"],
                )
            )
        else:
            steps.append(stub("03-analyzers", "Skipped — no APK available to open analyzer selection."))

        # 04 Scanning (+ optional live job)
        job_id = None
        report_url = None
        if do_scan and apk_key:
            page.goto(f"{base}/assess/analyzers?apk={apk_key}", wait_until="networkidle")
            configure_analyzers(page, analyzers)
            with page.expect_navigation(wait_until="domcontentloaded", timeout=60_000):
                page.click("#start-scan")
            # Capture /scan/ immediately — short jobs can redirect to /reports/ quickly.
            try:
                page.wait_for_url(re.compile(r".*/scan/[a-f0-9]+.*"), timeout=15_000)
            except Exception:
                pass
            m = re.search(r"/scan/([a-f0-9]+)", page.url)
            job_id = m.group(1) if m else None
            if job_id and "/reports/" not in page.url:
                try:
                    page.wait_for_selector("#scan-panel, #status-title", timeout=10_000)
                except Exception:
                    pass
                page.wait_for_timeout(600)
                steps.append(
                    shot(
                        page,
                        "04-scanning",
                        [f"Started job {job_id}"],
                    )
                )
            elif "/reports/" in page.url:
                # Extremely fast job: reconstruct a scanning view via status API is
                # gone; note the gap and still keep the report URL.
                report_url = page.url
                steps.append(
                    stub(
                        "04-scanning",
                        "Scan finished before a stable /scan/ screenshot could be taken "
                        f"(landed on {report_url}).",
                    )
                )
            else:
                steps.append(stub("04-scanning", f"Unexpected URL after Start scan: {page.url}"))

            print("  waiting for scan to finish…")
            if "/reports/" in page.url:
                ok = True
                report_url = page.url
            else:
                ok = wait_scan_done(page)
                if ok and "/reports/" in page.url:
                    report_url = page.url
            if ok and report_url:
                if page.url != report_url:
                    page.goto(report_url, wait_until="networkidle")
                else:
                    page.wait_for_load_state("networkidle")
                page.wait_for_timeout(800)
                steps.append(shot(page, "05-report", [f"Report URL: {report_url}"]))
            else:
                steps.append(
                    stub(
                        "05-report",
                        "Scan did not finish in time or failed — report screenshot unavailable.",
                    )
                )
        else:
            reason = "Scan skipped (--no-scan)." if not do_scan else "No APK to start a scan."
            steps.append(stub("04-scanning", reason))
            steps.append(stub("05-report", "Depends on a completed scan job."))

        # 06 Device
        page.goto(f"{base}/device", wait_until="networkidle")
        page.wait_for_selector("header.page-head")
        steps.append(shot(page, "06-device"))

        # 07 Exploit — only if we have a live report with an exploit link
        exploit_notes: list[str] = []
        if report_url:
            page.goto(report_url, wait_until="networkidle")
            link = page.locator('a.exploit, a[href*="/exploit?"]').first
            if link.count() > 0:
                href = link.get_attribute("href") or ""
                if href.startswith("/"):
                    href = base + href
                page.goto(href, wait_until="networkidle")
                page.wait_for_selector("header.page-head, form, .card")
                steps.append(shot(page, "07-exploit", ["Opened via finding link from the live report."]))
            else:
                # Try constructing from report name + first finding index
                name = report_url.rstrip("/").split("/")[-1]
                page.goto(f"{base}/exploit?report={name}&i=0", wait_until="domcontentloaded")
                if page.locator("header.page-head").count() and "404" not in page.title():
                    steps.append(shot(page, "07-exploit", [f"Opened /exploit?report={name}&i=0"]))
                else:
                    steps.append(
                        stub(
                            "07-exploit",
                            "Live report had no exploitable finding link for index 0.",
                        )
                    )
        else:
            steps.append(
                stub(
                    "07-exploit",
                    "Requires a live in-memory report from this server session "
                    "(is_live_report). Run without --no-scan to capture this screen.",
                )
            )

        # 08 Decompile — start job for a quick in-progress (or done) shot
        if apk_key:
            page.goto(f"{base}/assess", wait_until="networkidle")
            pick_apk_key(page, apk_key)
            form = page.locator("#pick-form")
            if form.count():
                with page.expect_navigation(wait_until="domcontentloaded", timeout=60_000):
                    page.locator('#pick-form button[type="submit"]:not([formmethod])').click()
                page.wait_for_timeout(800)
                if "/decompile/" in page.url:
                    try:
                        page.wait_for_selector("#scan-panel, #status-title, .deck", timeout=30_000)
                    except Exception:
                        pass
                    page.wait_for_timeout(800)
                    steps.append(
                        shot(
                            page,
                            "08-decompile",
                            [
                                "Decompile job started from Assessment. Full apktool/jadx "
                                "completion may take longer than this demo capture."
                            ],
                        )
                    )
                else:
                    # Likely redirected back with flash (missing apktool/jadx, etc.)
                    notice = ""
                    try:
                        notice = page.locator(".notice").first.inner_text(timeout=2000)
                    except Exception:
                        notice = "Decompile did not open /decompile/<job_id>."
                    steps.append(
                        shot(
                            page,
                            "08-decompile",
                            [
                                "Decompile UI gap: job did not start (tools missing or "
                                f"validation failed). Assessment page captured instead. {notice}"
                            ],
                        )
                    )
            else:
                steps.append(stub("08-decompile", "Decompile form not found on Assessment."))
        else:
            steps.append(stub("08-decompile", "Skipped — no APK to decompile."))

        browser.close()

    manifest = {
        "base_url": base,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "apk": apk_key,
        "analyzers": analyzers if do_scan else [],
        "steps": steps,
    }
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path = SHOT_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {manifest_path}")

    # Refresh HTML report
    gen = DEMO_DIR / "generate_report.py"
    if gen.is_file():
        import runpy

        sys.argv = [str(gen)]
        runpy.run_path(str(gen), run_name="__main__")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture androsec web UI demo screenshots")
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    parser.add_argument("--apk", default=DEFAULT_APK, help="APK radio value, e.g. root:DivaApplication.apk")
    parser.add_argument(
        "--analyzers",
        default=",".join(DEFAULT_ANALYZERS),
        help="Comma-separated static analyzer ids for the demo scan",
    )
    parser.add_argument("--no-scan", action="store_true", help="Do not start a live scan job")
    parser.add_argument("--headed", action="store_true", help="Show the browser window")
    args = parser.parse_args()
    analyzers = [a.strip() for a in args.analyzers.split(",") if a.strip()]
    return run(args.base_url, args.apk, analyzers, do_scan=not args.no_scan, headed=args.headed)


if __name__ == "__main__":
    raise SystemExit(main())
