"""Print layout for an androsec assessment. This is not the on-screen HTML report."""

import html
import os

from reporter.report_generator import sorted_findings


DISCLAIMER = (
    "This report is an automated assessment and provides an approximate security "
    "overview. It is not guaranteed to be 100% accurate. Some vulnerabilities may "
    "not have been detected."
)

_METHODOLOGY = (
    "This assessment combines static APK analysis (manifest, components, secrets, "
    "crypto/SQL/WebView patterns, SBOM fingerprints, lab-challenge mapping, and "
    "multi-signal correlation) with optional dynamic tooling (ADB, UIAutomator, "
    "run-as backup extraction, Frida, logcat) when a compatible device is available. "
    "Findings are graded by severity (Critical / High / Medium / Low / Info) and "
    "confidence. The risk score uses severity × confidence weights, capped at 100. "
    "Resilience controls (root/Frida/Xposed/debug/emulator detection) and lab-challenge "
    "inventory rows are informational coverage aids, not always exploitable vulns. "
    "OWASP MASVS mappings contextualise each finding against the mobile security standard."
)


def _esc(value):
    return html.escape("" if value is None else str(value))


def _rule(value):
    """Keep long rule ids inside the column, breaking after an underscore."""
    return _esc(value).replace("_", "_&#8203;")


def _tool_count(tool):
    """Return a known count, or None when this record never stored one."""
    if "finding_count" in tool and tool["finding_count"] is not None:
        return tool["finding_count"]
    if tool.get("findings") is not None:
        return len(tool["findings"])
    return None


def _categories(findings):
    counts = {}
    for finding in findings:
        masvs = finding.get("masvs") or "N/A"
        if str(masvs).startswith("MASVS-"):
            cat = str(masvs).split("-")[1]
        else:
            cat = "OTHER"
        counts[cat] = counts.get(cat, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def render_html(report):
    meta = report.metadata
    summary = report.summary
    findings = sorted_findings(report.findings)
    executed = [tool for tool in report.tool_results if not tool.get("skipped")]
    skipped = [tool for tool in report.tool_results if tool.get("skipped")]
    target = meta.get("target_basename") or os.path.basename(str(meta.get("target") or "APK"))
    level = summary.get("level") or "UNKNOWN"
    score = summary.get("score", 0)
    counts = summary.get("counts") or {}

    parts = [_document_start(target), _cover(meta, target), '<main class="body">']
    parts.append(_target_section(meta))
    parts.append(_summary_section(level, score, counts, findings))
    parts.append(_findings_table(findings))
    parts.append(_finding_details(findings))
    parts.append(_tools_section(executed, skipped))
    parts.append(_closing())
    parts.append("</main></body></html>")
    return "".join(parts)


def write_pdf(report, path):
    from weasyprint import HTML

    HTML(string=render_html(report), base_url=os.path.dirname(os.path.abspath(path))).write_pdf(path)


def _document_start(target):
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>androsec Security Assessment — {_esc(target)}</title>
<style>
@page {{
  size: A4;
  margin: 16mm 14mm 18mm 14mm;
  @top-left {{
    content: "androsec  ·  Security Assessment";
    font-family: "Liberation Sans", "DejaVu Sans", sans-serif;
    font-size: 8.5pt;
    color: #2B3A55;
  }}
  @top-right {{
    content: string(targetname);
    font-family: "Liberation Sans", "DejaVu Sans", sans-serif;
    font-size: 8.5pt;
    color: #2B3A55;
  }}
  @bottom-left {{
    content: "Automated assessment. Approximate overview — not a completeness guarantee.";
    font-family: "Liberation Sans", "DejaVu Sans", sans-serif;
    font-size: 8pt;
    color: #5c6b82;
  }}
  @bottom-right {{
    content: "Page " counter(page) " of " counter(pages);
    font-family: "Liberation Sans", "DejaVu Sans", sans-serif;
    font-size: 8.5pt;
    color: #2B3A55;
  }}
}}
@page cover {{
  size: A4;
  margin: 0;
  @top-left {{ content: none; }}
  @top-right {{ content: none; }}
  @bottom-left {{ content: none; }}
  @bottom-right {{ content: none; }}
}}
* {{ box-sizing: border-box; }}
html, body {{
  margin: 0;
  padding: 0;
  color: #070B14;
  font-family: "Liberation Sans", "DejaVu Sans", sans-serif;
  font-size: 10.5pt;
  line-height: 1.45;
}}
.target-name {{
  string-set: targetname content();
  position: absolute;
  width: 0;
  height: 0;
  overflow: hidden;
  color: transparent;
}}
h2 {{
  margin: 0 0 8px;
  font-size: 16pt;
  letter-spacing: -0.02em;
  color: #070B14;
  break-after: avoid;
}}
h2.break {{ break-before: page; }}
main > section {{ break-before: page; }}
main > section:first-child {{ break-before: auto; }}
h3 {{ margin: 0; font-size: 12pt; break-after: avoid; }}
h4 {{
  margin: 8px 0 2px;
  font-size: 8.5pt;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #2B3A55;
  break-after: avoid;
}}
p {{ margin: 0 0 8px; }}
.lead {{ color: #2B3A55; }}
.cover {{
  page: cover;
  position: relative;
  box-sizing: border-box;
  width: 210mm;
  height: 297mm;
  padding: 22mm 18mm 18mm;
  background: #070B14;
  color: #F5F8FF;
  overflow: hidden;
  break-after: page;
}}
.mark {{ width: 34mm; height: 16mm; }}
.word {{
  margin: 6mm 0 0;
  font-size: 28pt;
  font-weight: 700;
  letter-spacing: -0.04em;
}}
.word span {{ color: #B8FF30; }}
.kicker {{
  margin: 14mm 0 2mm;
  color: #19F9E0;
  font-size: 9pt;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}}
.cover h1 {{
  margin: 0;
  max-width: 150mm;
  font-size: 26pt;
  line-height: 1.1;
  letter-spacing: -0.03em;
  font-weight: 700;
}}
.cover-target {{
  margin: 8mm 0 0;
  font-size: 14pt;
  color: #B8FF30;
  word-break: break-all;
}}
.cover-meta {{ margin: 6mm 0 0; color: #F5F8FF; font-size: 11pt; }}
.cover-meta div {{ margin: 1.5mm 0; }}
.disclaimer {{
  position: absolute;
  left: 0;
  right: 0;
  bottom: 16mm;
  border: 1px solid #B8FF30;
  border-radius: 3mm;
  padding: 5mm 5.5mm;
}}
.disclaimer strong {{
  display: block;
  margin-bottom: 2mm;
  color: #B8FF30;
  font-size: 8.5pt;
  letter-spacing: 0.12em;
}}
.disclaimer p {{ margin: 0; font-size: 10.5pt; line-height: 1.45; }}
.meta, .counts, .findings {{
  width: 100%;
  border-collapse: collapse;
  margin: 2mm 0 6mm;
}}
.meta th, .counts th, .findings th {{
  background: #070B14;
  color: #F5F8FF;
  text-align: left;
  font-size: 8pt;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  padding: 2.2mm 2mm;
}}
.findings th {{
  font-size: 7.5pt;
  letter-spacing: 0.02em;
  white-space: nowrap;
}}
.meta td, .counts td, .findings td {{
  border-bottom: 0.3mm solid #d5deea;
  padding: 2mm;
  vertical-align: top;
  font-size: 9pt;
  overflow-wrap: anywhere;
}}
.findings thead {{ display: table-header-group; }}
.findings tr {{ break-inside: avoid; }}
.meta td:first-child {{ width: 42mm; font-weight: 700; color: #2B3A55; }}
.counts td {{ text-align: center; }}
.counts b {{ display: block; font-size: 14pt; }}
.risk {{
  margin: 0 0 4mm;
  font-size: 13pt;
}}
.risk b {{ color: #070B14; }}
.cats {{ margin: 0 0 4mm; }}
.cat {{
  display: inline-block;
  margin: 0 2mm 2mm 0;
  padding: 1mm 2.4mm;
  border-radius: 3mm;
  background: #e7eef8;
  color: #2B3A55;
  font-size: 9pt;
}}
.findings {{ font-size: 8pt; table-layout: fixed; }}
.findings td {{ font-size: 8pt; overflow-wrap: anywhere; }}
.findings th:nth-child(1), .findings td:nth-child(1) {{ width: 9mm; }}
.findings th:nth-child(2), .findings td:nth-child(2) {{ width: 22mm; }}
.findings th:nth-child(3), .findings td:nth-child(3) {{ width: 28mm; }}
.findings th:nth-child(4), .findings td:nth-child(4) {{ width: 48mm; }}
.findings td:nth-child(4) {{ font-size: 7.5pt; }}
.findings th:nth-child(6), .findings td:nth-child(6) {{ width: 38mm; }}
.sev {{ font-weight: 700; }}
.sev-critical {{ color: #6c3483; }}
.sev-high {{ color: #c0392b; }}
.sev-medium {{ color: #d35400; }}
.sev-low {{ color: #9a7d0a; }}
.sev-info {{ color: #1a5276; }}
.finding {{
  margin: 0 0 5mm;
  padding: 3.5mm 4mm;
  border: 0.3mm solid #d5deea;
  border-left: 1.2mm solid #19F9E0;
  border-radius: 1.5mm;
  break-inside: avoid;
}}
.finding header {{ margin-bottom: 2mm; }}
.finding h3 {{ font-size: 11.5pt; }}
.facts {{ width: 100%; border-collapse: collapse; margin: 0; }}
.facts th {{
  width: 28mm;
  padding: 0.8mm 2mm 0.8mm 0;
  text-align: left;
  vertical-align: top;
  color: #2B3A55;
  font-size: 8pt;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  background: transparent;
}}
.facts td {{
  padding: 0.8mm 0;
  border: 0;
  font-size: 9.5pt;
  word-break: break-word;
}}
.mono, pre {{
  font-family: "Liberation Mono", "DejaVu Sans Mono", monospace;
  font-size: 8pt;
  white-space: pre-wrap;
  word-break: break-word;
}}
.tool {{
  margin: 0 0 5mm;
  break-inside: auto;
}}
.tool h3 {{ margin-bottom: 1.5mm; }}
.badge {{
  display: inline-block;
  margin-left: 2mm;
  padding: 0.4mm 1.8mm;
  border-radius: 2mm;
  background: #e7eef8;
  color: #2B3A55;
  font-size: 8pt;
  font-weight: 700;
  vertical-align: middle;
}}
pre {{
  margin: 0;
  padding: 2.5mm 3mm;
  background: #f4f7fb;
  border-left: 1mm solid #19F9E0;
  color: #070B14;
}}
.closing {{
  margin-top: 6mm;
  padding: 4mm;
  border: 0.4mm solid #2B3A55;
  break-inside: avoid;
}}
.closing strong {{
  display: block;
  margin-bottom: 1.5mm;
  letter-spacing: 0.1em;
  font-size: 8.5pt;
  text-transform: uppercase;
}}
</style></head><body>
<span class="target-name">{_esc(target)}</span>
"""


def _cover(meta, target):
    package = meta.get("package") or "Unknown"
    version = meta.get("version_name") or "Unknown"
    when = meta.get("timestamp") or "Unknown"
    return f"""
<section class="cover">
  <svg class="mark" viewBox="0 0 68 32" aria-hidden="true">
    <rect x="1" y="1" width="14" height="14" rx="3" fill="#19F9E0"/>
    <rect x="19" y="1" width="14" height="14" rx="3" fill="none" stroke="#2B3A55" stroke-width="1.6"/>
    <rect x="37" y="1" width="14" height="14" rx="3" fill="#B8FF30"/>
    <rect x="55" y="1" width="14" height="14" rx="3" fill="none" stroke="#2B3A55" stroke-width="1.6"/>
    <rect x="1" y="17" width="14" height="14" rx="3" fill="none" stroke="#2B3A55" stroke-width="1.6"/>
    <rect x="19" y="17" width="14" height="14" rx="3" fill="#B8FF30"/>
    <rect x="37" y="17" width="14" height="14" rx="3" fill="none" stroke="#2B3A55" stroke-width="1.6"/>
    <rect x="55" y="17" width="14" height="14" rx="3" fill="#B8FF30"/>
  </svg>
  <p class="word">andro<span>sec</span></p>
  <p class="kicker">Security assessment report</p>
  <h1>Automated Android application assessment</h1>
  <p class="cover-target">{_esc(target)}</p>
  <div class="cover-meta">
    <div>Package {_esc(package)}</div>
    <div>Version {_esc(version)}</div>
    <div>Scan time {_esc(when)}</div>
  </div>
  <div class="disclaimer">
    <strong>Disclaimer</strong>
    <p>{_esc(DISCLAIMER)}</p>
  </div>
</section>
"""


def _target_section(meta):
    rows = [
        ("Target", meta.get("target_basename", meta.get("target", "?"))),
        ("Package", meta.get("package", "?")),
        ("App name", meta.get("app_name", "?")),
        ("Version", meta.get("version_name", "?")),
        ("Min / Target SDK", f"{meta.get('min_sdk', '?')} / {meta.get('target_sdk', '?')}"),
        ("APK size", meta.get("size_human", "?")),
        ("Scan time", meta.get("timestamp", "?")),
        ("SHA-256", meta.get("sha256", "?")),
    ]
    body = "".join(
        f"<tr><td>{_esc(label)}</td><td>{_esc(value)}</td></tr>" for label, value in rows
    )
    return (
        '<section><h2>Assessment target</h2>'
        '<p class="lead">Identity of the application examined in this run.</p>'
        f'<table class="meta"><tbody>{body}</tbody></table></section>'
    )


def _summary_section(level, score, counts, findings):
    cells = []
    for name in ("Critical", "High", "Medium", "Low", "Info"):
        cells.append(f"<td><b>{_esc(counts.get(name, 0))}</b>{_esc(name)}</td>")
    cats = _categories(findings)
    cat_html = ""
    if cats:
        chips = "".join(
            f'<span class="cat"><b>{n}</b> {_esc(cat.title())}</span>' for cat, n in cats
        )
        cat_html = f'<h4>Findings by category</h4><p class="cats">{chips}</p>'
    return (
        '<section><h2>Executive summary</h2>'
        f'<p class="risk">Risk level <b>{_esc(level)}</b> — score <b>{_esc(score)}/100</b></p>'
        f'<table class="counts"><tr>{"".join(cells)}</tr></table>'
        f'{cat_html}'
        f'<h4>Methodology</h4><p>{_esc(_METHODOLOGY)}</p></section>'
    )


def _findings_table(findings):
    if not findings:
        return (
            "<section><h2>Findings</h2>"
            "<p>No findings were identified.</p></section>"
        )
    rows = [
        "<thead><tr><th>#</th><th>Severity</th><th>Confidence</th><th>Rule</th>"
        "<th>Vulnerability</th><th>MASVS</th></tr></thead><tbody>"
    ]
    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity") or "Info"
        sev_class = "sev-" + severity.lower()
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f'<td><span class="sev {sev_class}">{_esc(severity)}</span></td>'
            f"<td>{_esc(finding.get('confidence') or 'High')}</td>"
            f"<td>{_rule(finding.get('rule_id'))}</td>"
            f"<td>{_esc(finding.get('title'))}</td>"
            f"<td>{_esc(finding.get('masvs') or 'N/A')}</td>"
            "</tr>"
        )
    return (
        '<section><h2>Findings</h2>'
        '<p class="lead">Evidence and the recommendation for each row are in the next section.</p>'
        f'<table class="findings">{"".join(rows)}</tbody></table></section>'
    )


def _finding_details(findings):
    if not findings:
        return ""
    blocks = []
    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity") or "Info"
        sev_class = "sev-" + severity.lower()
        description = (finding.get("description") or "").strip()
        desc_html = f"<p>{_esc(description)}</p>" if description else ""
        blocks.append(
            '<article class="finding">'
            f'<header><h3><span class="sev {sev_class}">{_esc(severity)}</span> '
            f'{index}. {_esc(finding.get("title") or finding.get("rule_id"))}</h3></header>'
            "<table class=\"facts\">"
            f"<tr><th>Rule</th><td>{_esc(finding.get('rule_id'))}</td></tr>"
            f"<tr><th>Confidence</th><td>{_esc(finding.get('confidence') or 'High')}</td></tr>"
            f"<tr><th>MASVS</th><td>{_esc(finding.get('masvs') or 'N/A')}</td></tr>"
            "</table>"
            f"{desc_html}"
            f"<h4>Evidence</h4><p class=\"mono\">{_esc(finding.get('evidence'))}</p>"
            f"<h4>Recommendation</h4><p>{_esc(finding.get('recommendation'))}</p>"
            "</article>"
        )
    return (
        "<section><h2>Detailed findings</h2>"
        + "".join(blocks)
        + "</section>"
    )


def _tool_block(tool):
    count = _tool_count(tool)
    if tool.get("skipped"):
        badge = '<span class="badge">Skipped</span>'
    elif count is None:
        badge = ""
    else:
        label = "1 finding" if count == 1 else f"{count} findings"
        badge = f'<span class="badge">{_esc(label)}</span>'
    output = tool.get("output") or ""
    return (
        '<article class="tool">'
        f'<h3>{_esc(tool.get("tool"))} {badge}</h3>'
        f"<pre>{_esc(output)}</pre>"
        "</article>"
    )


def _tools_section(executed, skipped):
    parts = [
        '<section><h2>Tool outputs</h2>',
        '<p class="lead">Each analyzer that ran, followed by tools that were skipped.</p>',
    ]
    if executed:
        parts.extend(_tool_block(tool) for tool in executed)
    else:
        parts.append("<p>No analyzer output was recorded.</p>")
    if skipped:
        parts.append("<h2>Skipped tools</h2>")
        parts.append(
            "<p class=\"lead\">These analyzers require a live ADB device or Frida server "
            "and did not run in this session.</p>"
        )
        parts.extend(_tool_block(tool) for tool in skipped)
    parts.append("</section>")
    return "".join(parts)


def _closing():
    return (
        '<section class="closing">'
        "<strong>Disclaimer</strong>"
        f"<p>{_esc(DISCLAIMER)}</p>"
        "</section>"
    )
