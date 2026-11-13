import html
import json
import os
from urllib.parse import urlencode

from rules.owasp_mapper import masvs_link as masvs_cell


SEV_COLOR = {
    "Critical": "#8e44ad",
    "High": "#e74c3c",
    "Medium": "#e67e22",
    "Low": "#f1c40f",
    "Info": "#3498db",
}
CONF_COLOR = {"High": "#27ae60", "Medium": "#f39c12", "Low": "#95a5a6"}
LEVEL_COLOR = {"CRITICAL": "#8e44ad", "HIGH": "#e74c3c",
               "MEDIUM": "#e67e22", "LOW": "#f1c40f",
               "PASS": "#27ae60"}
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
<title>androidsec Report — {esc(m.get('target_basename', m['target']))}</title>
<style>
body{{font-family:Arial,sans-serif;margin:30px;background:#f4f6f9;color:#333}}
a{{color:#1a5276}}
h1,h2{{color:#2c3e50}}.card{{background:#fff;padding:20px;border-radius:8px;
  box-shadow:0 2px 4px rgba(0,0,0,.08);margin-bottom:22px}}
pre{{background:#1e1e1e;color:#0f0;padding:14px;border-radius:5px;overflow-x:auto;
  white-space:pre-wrap;font-family:monospace;font-size:13px}}
table{{width:100%;border-collapse:collapse;margin-top:10px}}
th,td{{padding:10px;border:1px solid #ddd;text-align:left;vertical-align:top;font-size:14px}}
th{{background:#2c3e50;color:#fff}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;color:#fff;font-weight:700;font-size:12px}}
a.exploit{{display:inline-block;padding:4px 10px;border-radius:6px;background:#7a1f1f;color:#fff;text-decoration:none;font-weight:700;font-size:12px}}
a.exploit:hover{{background:#9f2d3a}}
.meta td{{border:0;padding:4px}}
.summary{{display:flex;gap:16px;flex-wrap:wrap}}
.summary div{{flex:1;min-width:120px;padding:14px;border-radius:6px;background:#ecf0f1;text-align:center}}
.summary b{{display:block;font-size:22px}}
.cat{{display:inline-block;padding:4px 10px;margin:4px 6px 4px 0;border-radius:14px;
  background:#ecf0f1;font-size:13px}}
.methodology p{{font-size:14px;line-height:1.55}}
</style></head><body>
<h1>androidsec — Integrated Security Assessment</h1>"""]

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
        lcolor = LEVEL_COLOR.get(level, "#333")
        parts.append(f'<div class="card"><h2>Executive Summary</h2>'
                     f'<h3 style="color:{lcolor}">Risk Level: {esc(level)} '
                     f'— Score {s["score"]}/100</h3>'
                     '<div class="summary">')
        for k in ("Critical", "High", "Medium", "Low", "Info"):
            parts.append(f'<div><b>{s["counts"].get(k, 0)}</b>{k}</div>')
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
                sc = SEV_COLOR.get(f["severity"], "#333")
                cc = CONF_COLOR.get(f.get("confidence", "High"), "#95a5a6")
                query = urlencode({"report": report_name, "i": str(index)})
                href = esc(f"/exploit?{query}")
                parts.append(
                    f'<tr>'
                    f'<td><span class="badge" style="background:{sc}">{esc(f["severity"])}</span></td>'
                    f'<td><span class="badge" style="background:{cc}">{esc(f.get("confidence","High"))}</span></td>'
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
            badge_color = "#27ae60" if n == 0 else "#e67e22"
            parts.append(f'<h3>{esc(t["tool"])} '
                         f'<span class="badge" style="background:{badge_color}">{n} findings</span></h3>')
            parts.append(f'<pre>{esc(t["output"])}</pre>')
        parts.append('</div>')

        # ---------- Skipped tools ----------
        if skipped:
            parts.append('<div class="card"><h2>Skipped Tools</h2>'
                         '<p style="font-size:14px;color:#666">'
                         'These analyzers require a live ADB device or Frida server '
                         'and did not run in this session.</p>')
            for t in skipped:
                parts.append(f'<h3>{esc(t["tool"])} '
                             f'<span class="badge" style="background:#95a5a6">SKIPPED</span></h3>'
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
