# androsec Website Demo Generator

Automated Playwright walkthrough of the local Flask UI, plus a polished
self-contained HTML demo report for the King Saud University graduation project.

## What you get

| Path | Purpose |
|------|---------|
| `demo_walkthrough.py` | Opens `http://127.0.0.1:5000` and captures numbered screenshots |
| `generate_report.py` | Builds `demo-report.html` from `screenshots/` + step metadata |
| `screenshots/` | `01-home.png`, `02-assessment.png`, … |
| `demo-report.html` | Graduation-demo report (relative image paths) |

## Prerequisites

1. Python 3.10+
2. Project dependencies installed (`pip install -r ../requirements.txt`)
3. Local web UI running on port 5000

```bash
# from repo root
python -m webapp.app
# → http://127.0.0.1:5000
```

## Install demo deps

```bash
cd demo
pip install -r requirements.txt
playwright install chromium
```

## Run the walkthrough

With the server already up:

```bash
python demo_walkthrough.py
```

Options:

```bash
python demo_walkthrough.py --base-url http://127.0.0.1:5000
python demo_walkthrough.py --no-scan          # skip starting a live scan
python demo_walkthrough.py --apk root:DivaApplication.apk
```

The script:

1. Checks that the home page responds
2. Walks Home → Assessment → Analyzer selection
3. Starts a short **static-only** scan (default: `apk_info`, `manifest`, `permission`) when a sample APK is available
4. Captures Scanning, then waits for the HTML report when the job finishes
5. Opens Device, and attempts Exploit / Decompile UI when reachable
6. Writes `screenshots/manifest.json` describing each step
7. Invokes `generate_report.py` to refresh `demo-report.html`

If no sample APK is listed in the Assessment library, the script still
screenshots the upload / empty library UI and notes the gap in the report.

## Regenerate the HTML only

```bash
python generate_report.py
```

Uses `screenshots/manifest.json` when present; otherwise discovers
`screenshots/*.png` in numeric order.

## Notes

- Does **not** redesign the webapp — it only captures the current UI.
- Brand palette in the report matches the product tokens: space ink / turquoise / lime / steel / snow.
- Leave the Flask server running while you walk; the demo scripts do not stop it.
