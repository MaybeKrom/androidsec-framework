import html
import json
import os
from urllib.parse import urlencode

from rules.owasp_mapper import masvs_link as masvs_cell


# Screen report uses the androsec palette only. Classes, not extra hues.
SEV_CLASS = {
    "Critical": "sev-critical",
    "High": "sev-high",
    "Medium": "sev-medium",
    "Low": "sev-low",
    "Info": "sev-info",
}
CONF_CLASS = {"High": "conf-high", "Medium": "conf-medium", "Low": "conf-low"}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def sorted_findings(findings):
    """Same order as the HTML table, so an exploit link index stays stable.

    Severity first, then auto-exploit priority (providers/run-as before TLS FPs),
    then rule id for stability.
    """
    try:
        from webapp.exploit_grounding import exploit_priority
    except Exception:  # pragma: no cover — keep report gen usable without webapp
        def exploit_priority(_finding):
            return 0

    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity"), 9),
            -exploit_priority(item),
            item.get("rule_id") or "",
        ),
    )


class ReportGenerator:
    def __init__(self, metadata, tool_results, findings, summary):
        self.metadata = metadata
        self.tool_results = tool_results
        self.findings = findings
        self.summary = summary

    # ---------- JSON ----------
    def save_json(self, path):
        data = {
            "metadata":     self.metadata,
            "summary":      self.summary,
            "findings":     self.findings,
            "tool_outputs": [
                {"tool": t["tool"],
                 "output": t["output"],
                 "skipped": t.get("skipped", False),
                 "finding_count": len(t.get("findings") or [])}
                for t in self.tool_results
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    # ---------- HTML ----------
    def save_html(self, path):
        esc = html.escape
        m, s = self.metadata, self.summary

        executed = [t for t in self.tool_results if not t.get("skipped")]
        skipped  = [t for t in self.tool_results if t.get("skipped")]

        # Category summary (by MASVS prefix)
        cat_counts = {}
        for f in self.findings:
            masvs = f.get("masvs", "N/A")
            if masvs.startswith("MASVS-"):
                cat = masvs.split("-")[1]
            else:
                cat = "OTHER"
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        parts = [f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>androsec Report — {esc(m.get('target_basename', m['target']))}</title>
<style>
@font-face{{font-family:"Space Grotesk";font-style:normal;font-weight:600;font-display:swap;
  src:url("/static/fonts/space-grotesk-600.woff2") format("woff2")}}
@font-face{{font-family:"IBM Plex Sans";font-style:normal;font-weight:400;font-display:swap;
  src:url("/static/fonts/ibm-plex-sans-400.woff2") format("woff2")}}
@font-face{{font-family:"IBM Plex Sans";font-style:normal;font-weight:500;font-display:swap;
  src:url("/static/fonts/ibm-plex-sans-500.woff2") format("woff2")}}
@font-face{{font-family:"IBM Plex Mono";font-style:normal;font-weight:400;font-display:swap;
  src:url("/static/fonts/ibm-plex-mono-400.woff2") format("woff2")}}
*{{box-sizing:border-box}}
body{{margin:0;background:#070B14;color:#F5F8FF;
  font-family:"IBM Plex Sans","Liberation Sans",sans-serif;line-height:1.55;font-size:15px}}
a{{color:#19F0E0}} a:hover{{color:#B8FF3D}}
h1,h2,h3,.summary b{{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-weight:600;
  letter-spacing:-0.03em;color:#F5F8FF}}
h1{{width:min(1120px,calc(100% - 48px));margin:0 auto;padding:36px 0 8px;font-size:2rem}}
h2{{margin:0 0 12px;font-size:1.35rem}}
h3{{margin:18px 0 8px;font-size:1.05rem}}
.card{{width:min(1120px,calc(100% - 48px));margin:0 auto 18px;padding:22px 24px;
  background:#070B14;background:color-mix(in srgb,#2B3A55 28%,#070B14);
  border:1px solid #2B3A55;border-radius:4px}}
p{{margin:0 0 10px}}
pre{{background:#070B14;color:#F5F8FF;padding:14px;border-radius:4px;overflow-x:auto;
  white-space:pre-wrap;font-family:"IBM Plex Mono",monospace;font-size:12.5px;line-height:1.5;
  border:1px solid #2B3A55;border-left:3px solid #19F0E0}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{padding:10px 12px;border-bottom:1px solid #2B3A55;text-align:left;vertical-align:top;font-size:13.5px}}
th{{position:sticky;top:57px;background:#070B14;color:#19F0E0;font-size:11px;letter-spacing:0.08em;
  text-transform:uppercase;font-weight:600}}
td code{{font-family:"IBM Plex Mono",monospace;font-size:12px;color:#F5F8FF}}
.badge{{display:inline-block;padding:2px 8px;border-radius:3px;color:#070B14;font-weight:600;
  font-size:11px;letter-spacing:0.04em;text-transform:uppercase;background:#2B3A55}}
.sev-critical,.found,.conf-high{{background:#B8FF3D;color:#070B14}}
.sev-high,.conf-medium,.clear{{background:#19F0E0;color:#070B14}}
.sev-medium,.conf-low,.skip{{background:#2B3A55;color:#F5F8FF}}
.sev-low{{background:transparent;color:#F5F8FF;box-shadow:inset 0 0 0 1px #2B3A55}}
.sev-info{{background:transparent;color:#19F0E0;box-shadow:inset 0 0 0 1px #19F0E0}}
a.exploit{{display:inline-block;padding:4px 10px;border-radius:4px;background:#B8FF3D;color:#070B14;
  text-decoration:none;font-weight:600;font-size:12px}}
a.exploit:hover{{background:#F5F8FF;color:#070B14}}
.meta td{{border:0;padding:6px 12px 6px 0}}
.meta td:first-child{{width:168px;color:#19F0E0;font-size:12px;letter-spacing:0.06em;text-transform:uppercase}}
.summary{{display:grid;grid-template-columns:repeat(5,1fr);border-top:1px solid #2B3A55;border-bottom:1px solid #2B3A55}}
.summary div{{padding:14px 12px 14px 0;background:transparent;border-radius:0;text-align:left}}
.summary div+div{{padding-left:12px;border-left:1px solid #2B3A55}}
.summary b{{display:block;font-size:1.8rem;letter-spacing:-0.04em}}
.count-critical b,.count-high b{{color:#B8FF3D}}
.count-medium b{{color:#19F0E0}}
.level-critical,.level-high{{color:#B8FF3D}}
.level-medium{{color:#19F0E0}}
.level-low,.level-pass{{color:#F5F8FF}}
.cat{{display:inline-block;padding:4px 0;margin:0 18px 0 0;background:transparent;font-size:13px;
  border-bottom:1px solid #2B3A55}}
.methodology p{{font-size:15px;line-height:1.6;color:color-mix(in srgb,#F5F8FF 72%,#2B3A55)}}
@media(max-width:720px){{
  h1,.card{{width:min(1120px,calc(100% - 28px))}}
  .summary{{grid-template-columns:1fr 1fr}}
  .summary div+div{{border-left:0}}
  table{{display:block;overflow-x:auto}}
}}
</style></head><body>
<h1>androsec — Integrated Security Assessment</h1>"""]

        # ---------- Metadata card ----------
        meta_rows = [
            ("Target",     m.get("target_basename", m["target"])),
            ("Package",    m.get("package", "?")),
            ("App name",   m.get("app_name", "?")),
            ("Version",    m.get("version_name", "?")),
            ("Min / Target SDK", f"{m.get('min_sdk','?')} / {m.get('target_sdk','?')}"),
            ("APK size",   m.get("size_human", "?")),
            ("Scan time",  m["timestamp"]),
            ("SHA-256",    m["sha256"]),
        ]
        parts.append('<div class="card"><table class="meta">')
        for k, v in meta_rows:
            parts.append(f'<tr><td style="width:160px"><b>{esc(k)}</b></td>'
                         f'<td style="word-break:break-all">{esc(str(v))}</td></tr>')
        parts.append("</table></div>")

        # ---------- Executive summary ----------
        level = s["level"]
        level_class = "level-" + esc(str(level).lower())
        parts.append(f'<div class="card"><h2>Executive Summary</h2>'
                     f'<h3 class="{level_class}">Risk Level: {esc(level)} '
                     f'— Score {s["score"]}/100</h3>'
                     '<div class="summary">')
        for k in ("Critical", "High", "Medium", "Low", "Info"):
            parts.append(
                f'<div class="count-{k.lower()}"><b>{s["counts"].get(k, 0)}</b>{k}</div>'
            )
        parts.append('</div>')

        if cat_counts:
            parts.append('<h3 style="margin-top:18px">Findings by Category</h3><div>')
            for cat, n in sorted(cat_counts.items(), key=lambda x: -x[1]):
                parts.append(f'<span class="cat"><b>{n}</b> {esc(cat.title())}</span>')
            parts.append('</div>')
        parts.append('</div>')

        # ---------- Findings table ----------
        parts.append('<div class="card"><h2>Findings</h2>')
        if not self.findings:
            parts.append('<p>No findings were identified.</p>')
        else:
            parts.append('<table><tr><th>Severity</th><th>Confidence</th><th>Rule</th>'
                         '<th>Vulnerability</th><th>Evidence</th><th>Recommendation</th>'
                         '<th>MASVS</th><th>Exploit</th></tr>')
            report_name = os.path.basename(path)
            for index, f in enumerate(sorted_findings(self.findings)):
                sev = SEV_CLASS.get(f["severity"], "sev-info")
                conf = CONF_CLASS.get(f.get("confidence", "High"), "conf-low")
                query = urlencode({"report": report_name, "i": str(index)})
                href = esc(f"/exploit?{query}")
                parts.append(
                    f'<tr>'
                    f'<td><span class="badge {sev}">{esc(f["severity"])}</span></td>'
                    f'<td><span class="badge {conf}">{esc(f.get("confidence","High"))}</span></td>'
                    f'<td><code>{esc(f["rule_id"])}</code></td>'
                    f'<td>{esc(f.get("title",""))}</td>'
                    f'<td><code>{esc(f.get("evidence",""))}</code></td>'
                    f'<td>{esc(f.get("recommendation",""))}</td>'
                    f'<td>{masvs_cell(f.get("masvs", "N/A"))}</td>'
                    f'<td><a class="exploit" href="{href}">Exploit</a></td>'
                    f'</tr>'
                )
            parts.append('</table>')
        parts.append('</div>')

        # ---------- Methodology ----------
        parts.append(
            '<div class="card methodology"><h2>Methodology</h2><p>'
            'This assessment was performed through static analysis of the supplied APK, '
            'complemented by optional runtime tooling (ADB, Frida) when a compatible '
            'device was available. Findings are graded by <b>severity</b> '
            '(Critical / High / Medium / Low / Info) and assigned a <b>confidence</b> '
            'level based on the detection method. The risk score is derived from '
            'severity × confidence weights, capped at 100. Resilience controls '
            '(root/frida/xposed/debug/emulator detection) are reported as '
            '<i>informational</i> observations of positive defences, not as '
            'vulnerabilities. OWASP MASVS mappings are provided for each finding to '
            'contextualise results against the mobile security standard.'
            '</p></div>'
        )

        # ---------- Executed tool outputs ----------
        parts.append('<div class="card"><h2>Executed Tools</h2>')
        for t in executed:
            n = len(t["findings"])
            badge_class = "clear" if n == 0 else "found"
            parts.append(f'<h3>{esc(t["tool"])} '
                         f'<span class="badge {badge_class}">{n} findings</span></h3>')
            parts.append(f'<pre>{esc(t["output"])}</pre>')
        parts.append('</div>')

        # ---------- Skipped tools ----------
        if skipped:
            parts.append('<div class="card"><h2>Skipped Tools</h2>'
                         '<p class="methodology">These analyzers require a live ADB device or Frida server '
                         'and did not run in this session.</p>')
            for t in skipped:
                parts.append(f'<h3>{esc(t["tool"])} '
                             f'<span class="badge skip">SKIPPED</span></h3>'
                             f'<pre>{esc(t["output"])}</pre>')
            parts.append('</div>')

        parts.append("</body></html>")

        with open(path, "w", encoding="utf-8") as f:
            f.write("".join(parts))

    def render_pdf_html(self):
        from reporter.pdf_report import render_html
        return render_html(self)

    def save_pdf(self, path):
        from reporter.pdf_report import write_pdf
        write_pdf(self, path)
