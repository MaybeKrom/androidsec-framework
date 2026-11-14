#!/usr/bin/env python3
"""Build demo/demo-report.html from screenshots/manifest.json (or PNGs)."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
SHOT_DIR = DEMO_DIR / "screenshots"
OUT_HTML = DEMO_DIR / "demo-report.html"

FALLBACK_COPY = {
    "01-home": (
        "Home",
        "/",
        "Landing page for the androsec assessment workspace.",
        "Introduces the King Saud University graduation project and the local VAPT workflow.",
    ),
    "02-assessment": (
        "Assessment — choose an APK",
        "/assess",
        "Upload or select a lab APK, then analyze or decompile.",
        "Sample APKs and uploads appear in the library before analyzer selection.",
    ),
    "03-analyzers": (
        "Analyzer selection",
        "/assess/analyzers",
        "Choose static and optional dynamic tools before the scan.",
        "Static tools default on; dynamic tools require device authorization.",
    ),
    "04-scanning": (
        "Scan progress",
        "/scan/<job_id>",
        "Live progress while each analyzer runs against the APK.",
        "Per-tool checklist and percent complete until the report is ready.",
    ),
    "05-report": (
        "Security report",
        "/reports/<filename>",
        "Evidence-backed HTML report with PDF download.",
        "Findings map to OWASP MASVS; Exploit opens from individual rows.",
    ),
    "06-device": (
        "Device readiness",
        "/device",
        "Connect and authorize a phone or emulator for dynamic checks.",
        "adb serial selection, install helpers, and authorization gates.",
    ),
    "07-exploit": (
        "AI exploit & evidence",
        "/exploit",
        "Grounded PoC planning for a single finding (BYOK).",
        "API key used only for the request; evidence gate scores confirmation.",
    ),
    "08-decompile": (
        "Decompile workspace",
        "/decompile/<job_id>",
        "apktool + jadx decode, browse, and rebuild.",
        "Browse resources or Java sources after decoding completes.",
    ),
}


def load_steps() -> tuple[list[dict], dict]:
    manifest_path = SHOT_DIR / "manifest.json"
    meta: dict = {}
    if manifest_path.is_file():
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        meta = {
            "base_url": data.get("base_url"),
            "generated_at": data.get("generated_at"),
            "apk": data.get("apk"),
            "analyzers": data.get("analyzers") or [],
        }
        return list(data.get("steps") or []), meta

    steps = []
    for path in sorted(SHOT_DIR.glob("*.png")):
        stem = path.stem
        title, route, summary, detail = FALLBACK_COPY.get(
            stem, (stem, "", "Captured screen.", "")
        )
        steps.append(
            {
                "id": stem,
                "file": path.name,
                "title": title,
                "route": route,
                "summary": summary,
                "detail": detail,
                "notes": [],
                "captured": True,
                "url": None,
            }
        )
    return steps, meta


def step_number(step_id: str, index: int) -> str:
    m = re.match(r"^(\d+)", step_id or "")
    return m.group(1) if m else f"{index + 1:02d}"


def render_step(step: dict, index: int) -> str:
    num = step_number(step.get("id") or "", index)
    title = html.escape(step.get("title") or step.get("id") or f"Step {num}")
    summary = html.escape(step.get("summary") or "")
    detail = html.escape(step.get("detail") or "")
    route = html.escape(step.get("route") or "")
    url = html.escape(step.get("url") or "")
    notes = [html.escape(n) for n in (step.get("notes") or []) if n]
    captured = bool(step.get("captured") and step.get("file"))
    file_name = step.get("file") or ""

    media = ""
    if captured:
        media = (
            f'<figure class="shot">'
            f'<img src="screenshots/{html.escape(file_name)}" '
            f'alt="{title} screenshot" loading="lazy" />'
            f"<figcaption>{html.escape(file_name)}</figcaption>"
            f"</figure>"
        )
    else:
        media = (
            '<div class="shot gap" role="img" aria-label="Screenshot unavailable">'
            "<strong>Screenshot gap</strong>"
            "<p>This screen was not reachable in the automated walk. "
            "See the note on the right.</p>"
            "</div>"
        )

    notes_html = ""
    if notes:
        items = "".join(f"<li>{n}</li>" for n in notes)
        notes_html = f'<ul class="notes">{items}</ul>'

    url_html = f'<p class="live-url"><span>Live URL</span> {url}</p>' if url else ""

    return f"""
    <article class="step" id="step-{html.escape(step.get('id') or num)}" style="--i:{index}">
      <div class="media">{media}</div>
      <div class="copy">
        <div class="step-meta">
          <span class="badge">Step {num}</span>
          <code class="route">{route}</code>
        </div>
        <h2>{title}</h2>
        <p class="summary">{summary}</p>
        <p class="detail">{detail}</p>
        {url_html}
        {notes_html}
      </div>
      <div class="connector" aria-hidden="true"></div>
    </article>
    """


def build_nav(steps: list[dict]) -> str:
    links = []
    for i, step in enumerate(steps):
        sid = step.get("id") or f"{i+1:02d}"
        num = step_number(sid, i)
        title = html.escape(step.get("title") or sid)
        links.append(
            f'<a href="#step-{html.escape(sid)}"><span>{num}</span>{title}</a>'
        )
    return "\n".join(links)


def build_html(steps: list[dict], meta: dict) -> str:
    when = html.escape(meta.get("generated_at") or "on demand")
    base = html.escape(meta.get("base_url") or "http://127.0.0.1:5000")
    apk = html.escape(meta.get("apk") or "—")
    analyzers = meta.get("analyzers") or []
    analyzers_html = (
        ", ".join(f"<code>{html.escape(a)}</code>" for a in analyzers) if analyzers else "—"
    )
    captured = sum(1 for s in steps if s.get("captured") and s.get("file"))
    body_steps = "\n".join(render_step(s, i) for i, s in enumerate(steps))
    nav = build_nav(steps)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>androsec — Automated Website Demo</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Serif:wght@500;600&display=swap" rel="stylesheet" />
  <style>
    :root {{
      --space-ink: #070B14;
      --surface: #0C1222;
      --surface-2: #10182A;
      --turquoise: #19F9E0;
      --lime: #B8FF30;
      --steel: #2B3A55;
      --snow: #F5F8FF;
      --muted: #9AA8C2;
      --line: rgba(43, 58, 85, 0.85);
      --radius: 18px;
      --shadow: 0 24px 60px rgba(0, 0, 0, 0.35);
      --font: "IBM Plex Sans", "Segoe UI", sans-serif;
      --display: "IBM Plex Serif", Georgia, serif;
    }}

    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      font-family: var(--font);
      color: var(--snow);
      background:
        radial-gradient(900px 420px at 12% -8%, rgba(25, 249, 224, 0.12), transparent 55%),
        radial-gradient(700px 380px at 92% 8%, rgba(184, 255, 48, 0.08), transparent 50%),
        linear-gradient(180deg, #05080F 0%, var(--space-ink) 40%, #05080F 100%);
      line-height: 1.55;
      min-height: 100vh;
    }}

    a {{ color: var(--turquoise); text-decoration: none; }}
    a:hover {{ color: var(--lime); }}
    code {{
      font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
      font-size: 0.86em;
      color: var(--turquoise);
    }}

    .shell {{
      width: min(1180px, calc(100% - 2.5rem));
      margin: 0 auto;
    }}

    .hero {{
      position: relative;
      padding: 4.5rem 0 3rem;
      overflow: hidden;
    }}
    .hero::before {{
      content: "";
      position: absolute;
      inset: 10% -10% auto auto;
      width: 420px;
      height: 420px;
      background:
        conic-gradient(from 210deg, rgba(25,249,224,0.18), transparent 40%, rgba(184,255,48,0.12), transparent 70%);
      filter: blur(8px);
      pointer-events: none;
    }}
    .kicker {{
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--muted);
    }}
    .kicker .dot {{
      width: 0.55rem;
      height: 0.55rem;
      border-radius: 2px;
      background: var(--lime);
      box-shadow: 0 0 0 4px rgba(184, 255, 48, 0.12);
    }}
    .brand {{
      margin: 1rem 0 0.35rem;
      font-family: var(--display);
      font-size: clamp(2.6rem, 5vw, 4rem);
      font-weight: 600;
      letter-spacing: -0.04em;
      line-height: 1.05;
    }}
    .brand span {{ color: var(--lime); }}
    .lede {{
      max-width: 38rem;
      margin: 0.85rem 0 0;
      color: var(--muted);
      font-size: 1.05rem;
    }}
    .meta-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem 1.25rem;
      margin-top: 1.75rem;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .meta-row strong {{ color: var(--snow); font-weight: 600; }}
    .cta-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-top: 1.75rem;
    }}
    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.7rem 1.1rem;
      border-radius: 999px;
      border: 1px solid var(--steel);
      background: transparent;
      color: var(--snow);
      font: inherit;
      font-weight: 600;
      cursor: pointer;
      transition: border-color 0.2s, background 0.2s, transform 0.2s;
    }}
    .btn:hover {{ border-color: var(--turquoise); transform: translateY(-1px); }}
    .btn.primary {{
      background: linear-gradient(135deg, rgba(25,249,224,0.18), rgba(184,255,48,0.14));
      border-color: rgba(25, 249, 224, 0.55);
      color: var(--snow);
    }}

    .layout {{
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      gap: 2rem;
      padding-bottom: 4rem;
      align-items: start;
    }}
    .toc {{
      position: sticky;
      top: 1.25rem;
      padding: 1rem;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: rgba(12, 18, 34, 0.72);
      backdrop-filter: blur(10px);
    }}
    .toc h2 {{
      margin: 0 0 0.85rem;
      font-size: 0.72rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 600;
    }}
    .toc a {{
      display: grid;
      grid-template-columns: 2rem 1fr;
      gap: 0.55rem;
      align-items: baseline;
      padding: 0.45rem 0.35rem;
      border-radius: 10px;
      color: var(--muted);
      font-size: 0.9rem;
      transition: background 0.2s, color 0.2s;
    }}
    .toc a span {{
      color: var(--lime);
      font-variant-numeric: tabular-nums;
      font-weight: 700;
      font-size: 0.8rem;
    }}
    .toc a:hover,
    .toc a.active {{
      background: rgba(25, 249, 224, 0.08);
      color: var(--snow);
    }}

    .timeline {{
      display: flex;
      flex-direction: column;
      gap: 1.75rem;
      position: relative;
    }}

    .step {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(0, 0.85fr);
      gap: 1.35rem;
      padding: 1.15rem;
      border: 1px solid var(--line);
      border-radius: calc(var(--radius) + 4px);
      background:
        linear-gradient(160deg, rgba(16, 24, 42, 0.92), rgba(12, 18, 34, 0.78));
      box-shadow: var(--shadow);
      opacity: 0;
      transform: translateY(18px);
      animation: rise 0.7s ease forwards;
      animation-delay: calc(var(--i) * 0.07s);
      position: relative;
    }}
    @keyframes rise {{
      to {{ opacity: 1; transform: none; }}
    }}
    .step:hover {{
      border-color: rgba(25, 249, 224, 0.35);
    }}
    .connector {{
      position: absolute;
      left: 1.55rem;
      bottom: -1.8rem;
      width: 2px;
      height: 1.8rem;
      background: linear-gradient(var(--turquoise), transparent);
      opacity: 0.45;
    }}
    .step:last-child .connector {{ display: none; }}

    .shot {{
      margin: 0;
      border-radius: 14px;
      overflow: hidden;
      border: 1px solid var(--line);
      background: #05080F;
      min-height: 220px;
    }}
    .shot img {{
      display: block;
      width: 100%;
      height: auto;
      vertical-align: middle;
    }}
    .shot figcaption {{
      padding: 0.45rem 0.7rem;
      font-size: 0.75rem;
      color: var(--muted);
      border-top: 1px solid var(--line);
      background: rgba(5, 8, 15, 0.9);
    }}
    .shot.gap {{
      display: grid;
      place-content: center;
      text-align: center;
      padding: 2rem 1.25rem;
      color: var(--muted);
      background:
        repeating-linear-gradient(
          -45deg,
          rgba(43, 58, 85, 0.25),
          rgba(43, 58, 85, 0.25) 8px,
          transparent 8px,
          transparent 16px
        ),
        var(--surface);
    }}
    .shot.gap strong {{ color: var(--lime); display: block; margin-bottom: 0.4rem; }}

    .copy {{
      display: flex;
      flex-direction: column;
      gap: 0.55rem;
      padding: 0.35rem 0.15rem 0.15rem;
    }}
    .step-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.55rem;
      align-items: center;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.55rem;
      border-radius: 999px;
      border: 1px solid rgba(184, 255, 48, 0.35);
      color: var(--lime);
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }}
    .route {{
      color: var(--muted);
      border: 1px solid var(--line);
      padding: 0.15rem 0.45rem;
      border-radius: 8px;
      background: rgba(5, 8, 15, 0.55);
    }}
    .copy h2 {{
      margin: 0.15rem 0 0;
      font-family: var(--display);
      font-size: 1.45rem;
      letter-spacing: -0.02em;
      line-height: 1.2;
    }}
    .summary {{
      margin: 0;
      color: var(--snow);
      font-weight: 500;
    }}
    .detail {{
      margin: 0;
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .live-url {{
      margin: 0.25rem 0 0;
      font-size: 0.82rem;
      color: var(--muted);
      word-break: break-all;
    }}
    .live-url span {{
      display: inline-block;
      margin-right: 0.35rem;
      color: var(--turquoise);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.68rem;
    }}
    .notes {{
      margin: 0.35rem 0 0;
      padding-left: 1.1rem;
      color: #F5C451;
      font-size: 0.88rem;
    }}

    .footer {{
      border-top: 1px solid var(--line);
      padding: 1.75rem 0 2.5rem;
      color: var(--muted);
      font-size: 0.9rem;
    }}
    .footer strong {{ color: var(--snow); }}

    @media (max-width: 960px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .toc {{ position: static; display: flex; flex-wrap: wrap; gap: 0.25rem 0.75rem; }}
      .toc h2 {{ width: 100%; }}
      .step {{ grid-template-columns: 1fr; }}
      .connector {{ display: none; }}
    }}

    @media (prefers-reduced-motion: reduce) {{
      html {{ scroll-behavior: auto; }}
      .step {{ animation: none; opacity: 1; transform: none; }}
    }}
  </style>
</head>
<body>
  <header class="hero">
    <div class="shell">
      <p class="kicker"><span class="dot" aria-hidden="true"></span> King Saud University · Graduation Project Demo</p>
      <h1 class="brand">andro<span>sec</span></h1>
      <p class="lede">
        Automated website walkthrough of the Android VAPT assessment framework —
        Home through Assessment, scanning, reporting, device readiness, exploit, and decompile.
      </p>
      <div class="meta-row">
        <div><strong>Captured</strong> {captured}/{len(steps)} screens</div>
        <div><strong>Target</strong> {base}</div>
        <div><strong>APK</strong> {apk}</div>
        <div><strong>Demo analyzers</strong> {analyzers_html}</div>
        <div><strong>Generated</strong> {when}</div>
      </div>
      <div class="cta-row">
        <a class="btn primary" href="#step-{(steps[0].get('id') if steps else '01-home')}">Start walkthrough</a>
        <button class="btn" type="button" id="toggle-auto">Auto-scroll timeline</button>
      </div>
    </div>
  </header>

  <div class="shell layout">
    <nav class="toc" aria-label="Demo steps">
      <h2>Timeline</h2>
      {nav}
    </nav>
    <main class="timeline">
      {body_steps}
    </main>
  </div>

  <footer class="footer">
    <div class="shell">
      <p>
        <strong>androsec</strong> — Android VAPT Assessment Framework ·
        College of Computer and Information Sciences · King Saud University.
        Screenshots were captured against the local Flask UI for authorized lab demonstration only.
      </p>
      <p>Regenerate with <code>python demo_walkthrough.py</code> or <code>python generate_report.py</code>.</p>
    </div>
  </footer>

  <script>
    (function () {{
      const links = Array.from(document.querySelectorAll(".toc a"));
      const steps = links.map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
      const io = new IntersectionObserver((entries) => {{
        entries.forEach((entry) => {{
          if (!entry.isIntersecting) return;
          const id = "#" + entry.target.id;
          links.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === id));
        }});
      }}, {{ rootMargin: "-35% 0px -55% 0px", threshold: 0.01 }});
      steps.forEach((el) => io.observe(el));

      let timer = null;
      const btn = document.getElementById("toggle-auto");
      if (btn) {{
        btn.addEventListener("click", () => {{
          if (timer) {{
            clearInterval(timer);
            timer = null;
            btn.textContent = "Auto-scroll timeline";
            return;
          }}
          let i = 0;
          btn.textContent = "Stop auto-scroll";
          const tick = () => {{
            if (i >= steps.length) {{
              clearInterval(timer);
              timer = null;
              btn.textContent = "Auto-scroll timeline";
              return;
            }}
            steps[i].scrollIntoView({{ behavior: "smooth", block: "start" }});
            i += 1;
          }};
          tick();
          timer = setInterval(tick, 3200);
        }});
      }}
    }})();
  </script>
</body>
</html>
"""


def main() -> int:
    steps, meta = load_steps()
    if not steps:
        print(f"No screenshots or manifest under {SHOT_DIR}")
        return 1
    html_text = build_html(steps, meta)
    OUT_HTML.write_text(html_text, encoding="utf-8")
    print(f"Wrote {OUT_HTML} ({len(steps)} steps)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
