"""Per-scan folder layout + index.json for assessment and exploitation evidence.

Canonical tree (see docs/scan-evidence-unification.md in the project store)::

    scans/scan_YYYYMMDD_HHMMSS_<SafeAppName>/
      index.json
      assessment_report.{html,json,pdf}
      security_report_YYYYMMDD_HHMMSS.{html,json,pdf}   # legacy basename
      evidence/
        traffic*.json / mitm dumps
        exploitation_<run_id>/...
      exploitation_report_<finding_id>_<run_id>.pdf

Folders + index.json are authoritative for offline traceability. SQLite in the
web UI remains a secondary "latest exploit" cache only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any

SCHEMA = 1
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_SCAN_ID = re.compile(r"^scan_\d{8}_\d{6}_[A-Za-z0-9._-]{1,80}$")
_STAMP = re.compile(r"security_report_(\d{8}_\d{6})\.(html|json|pdf)$")


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_scans_root() -> str:
    return os.path.join(project_root(), "scans")


def default_legacy_reports_root() -> str:
    return os.path.join(project_root(), "output_reports")


def safe_app_name(name: str | None, fallback: str = "App") -> str:
    raw = (name or "").strip() or fallback
    cleaned = _SAFE_NAME.sub("_", raw).strip("._-")
    if not cleaned:
        cleaned = "App"
    return cleaned[:60]


def make_scan_id(stamp: str, app_name: str) -> str:
    return f"scan_{stamp}_{safe_app_name(app_name)}"


def finding_id_for(index: int, rule_id: str | None) -> str:
    rule = _SAFE_NAME.sub("_", str(rule_id or "UNKNOWN").strip()) or "UNKNOWN"
    rule = rule[:80]
    return f"F{int(index):03d}_{rule}"


def stamp_from_legacy_report_name(report_name: str) -> str | None:
    match = _STAMP.fullmatch(os.path.basename(report_name or ""))
    return match.group(1) if match else None


def create_scan_dir(
    scans_root: str,
    stamp: str,
    app_name: str,
    *,
    package: str = "",
    apk_basename: str = "",
    sha256: str = "",
) -> dict[str, Any]:
    """Create ``scans_root/scan_<stamp>_<App>/`` with evidence/ and index.json."""
    scan_id = make_scan_id(stamp, app_name)
    scan_dir = os.path.join(scans_root, scan_id)
    evidence_dir = os.path.join(scan_dir, "evidence")
    os.makedirs(evidence_dir, exist_ok=True)

    index = {
        "schema": SCHEMA,
        "scan_id": scan_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "app_name": app_name or safe_app_name(app_name),
        "package": package or "",
        "apk_basename": apk_basename or "",
        "sha256": sha256 or "",
        "assessment": {
            "html": "assessment_report.html",
            "json": "assessment_report.json",
            "pdf": "assessment_report.pdf",
            "legacy_html": f"security_report_{stamp}.html",
            "legacy_json": f"security_report_{stamp}.json",
            "legacy_pdf": f"security_report_{stamp}.pdf",
        },
        "findings": [],
        "exploitations": [],
    }
    write_index(scan_dir, index)
    return {
        "scan_id": scan_id,
        "scan_dir": scan_dir,
        "evidence_dir": evidence_dir,
        "stamp": stamp,
        "index": index,
    }


def index_path(scan_dir: str) -> str:
    return os.path.join(scan_dir, "index.json")


def read_index(scan_dir: str) -> dict[str, Any]:
    path = index_path(scan_dir)
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("index.json must be an object")
    return data


def write_index(scan_dir: str, index: dict[str, Any]) -> str:
    os.makedirs(scan_dir, exist_ok=True)
    path = index_path(scan_dir)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(index, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp, path)
    return path


def findings_catalog(sorted_findings_list: list[dict]) -> list[dict[str, Any]]:
    rows = []
    for index, finding in enumerate(sorted_findings_list or []):
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "UNKNOWN")
        rows.append({
            "finding_id": finding_id_for(index, rule_id),
            "index": index,
            "rule_id": rule_id,
            "title": str(finding.get("title") or ""),
            "severity": str(finding.get("severity") or ""),
        })
    return rows


def write_assessment_bundle(
    scan_dir: str,
    stamp: str,
    reporter,
    *,
    sorted_findings_list: list[dict] | None = None,
    legacy_reports_dir: str | None = None,
) -> dict[str, str]:
    """Write assessment HTML/JSON under the scan dir (+ optional legacy dual-write).

    Returns paths keyed by role: assessment_html, assessment_json, legacy_html,
    legacy_json, and dual-written flat paths when ``legacy_reports_dir`` is set.
    """
    os.makedirs(scan_dir, exist_ok=True)
    assessment_html = os.path.join(scan_dir, "assessment_report.html")
    assessment_json = os.path.join(scan_dir, "assessment_report.json")
    legacy_html_name = f"security_report_{stamp}.html"
    legacy_json_name = f"security_report_{stamp}.json"
    legacy_html = os.path.join(scan_dir, legacy_html_name)
    legacy_json = os.path.join(scan_dir, legacy_json_name)

    # Write legacy-named HTML first so Exploit column hrefs use that basename.
    reporter.save_html(legacy_html)
    reporter.save_json(legacy_json)
    shutil.copyfile(legacy_html, assessment_html)
    shutil.copyfile(legacy_json, assessment_json)

    paths = {
        "assessment_html": assessment_html,
        "assessment_json": assessment_json,
        "legacy_html": legacy_html,
        "legacy_json": legacy_json,
        "html_path": legacy_html,
        "json_path": legacy_json,
    }

    if legacy_reports_dir:
        os.makedirs(legacy_reports_dir, exist_ok=True)
        flat_html = os.path.join(legacy_reports_dir, legacy_html_name)
        flat_json = os.path.join(legacy_reports_dir, legacy_json_name)
        shutil.copyfile(legacy_html, flat_html)
        shutil.copyfile(legacy_json, flat_json)
        from rules.owasp_mapper import install_explanations
        install_explanations(legacy_reports_dir)
        paths["flat_html"] = flat_html
        paths["flat_json"] = flat_json
        # Web UI / jobs historically point at the flat dual-write path.
        paths["html_path"] = flat_html
        paths["json_path"] = flat_json

    try:
        index = read_index(scan_dir)
    except (OSError, ValueError, json.JSONDecodeError):
        index = {"schema": SCHEMA, "scan_id": os.path.basename(scan_dir)}

    index["assessment"] = {
        "html": "assessment_report.html",
        "json": "assessment_report.json",
        "pdf": "assessment_report.pdf",
        "legacy_html": legacy_html_name,
        "legacy_json": legacy_json_name,
        "legacy_pdf": f"security_report_{stamp}.pdf",
    }
    if sorted_findings_list is not None:
        index["findings"] = findings_catalog(sorted_findings_list)
    write_index(scan_dir, index)
    return paths


def sync_assessment_pdf(scan_dir: str, stamp: str, pdf_source: str) -> dict[str, str]:
    """Copy a generated PDF into scan assessment + legacy names."""
    if not pdf_source or not os.path.isfile(pdf_source):
        return {}
    os.makedirs(scan_dir, exist_ok=True)
    assessment_pdf = os.path.join(scan_dir, "assessment_report.pdf")
    legacy_pdf = os.path.join(scan_dir, f"security_report_{stamp}.pdf")
    shutil.copyfile(pdf_source, assessment_pdf)
    if os.path.realpath(pdf_source) != os.path.realpath(legacy_pdf):
        shutil.copyfile(pdf_source, legacy_pdf)
    return {"assessment_pdf": assessment_pdf, "legacy_pdf": legacy_pdf}


def exploitation_evidence_dir(scan_dir: str, run_id: str) -> str:
    path = os.path.join(scan_dir, "evidence", run_id)
    os.makedirs(path, exist_ok=True)
    return path


def exploitation_pdf_name(finding_id: str, run_id: str) -> str:
    safe_fid = _SAFE_NAME.sub("_", finding_id).strip("._-") or "finding"
    safe_run = _SAFE_NAME.sub("_", run_id).strip("._-") or "run"
    return f"exploitation_report_{safe_fid}_{safe_run}.pdf"


def register_exploitation(
    scan_dir: str,
    *,
    finding_id: str,
    rule_id: str,
    index: int,
    run_id: str,
    confirmation: str = "",
    pdf_relpath: str | None = None,
    evidence_relpath: str | None = None,
) -> dict[str, Any]:
    """Append or replace an exploitation entry in index.json."""
    index_doc = read_index(scan_dir)
    exploits = list(index_doc.get("exploitations") or [])
    evidence_rel = evidence_relpath or os.path.join("evidence", run_id)
    pdf_rel = pdf_relpath or exploitation_pdf_name(finding_id, run_id)
    entry = {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "index": int(index),
        "run_id": run_id,
        "evidence_dir": evidence_rel.replace("\\", "/"),
        "pdf": pdf_rel.replace("\\", "/"),
        "confirmation": confirmation or "",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    replaced = False
    for i, existing in enumerate(exploits):
        if isinstance(existing, dict) and existing.get("run_id") == run_id:
            exploits[i] = entry
            replaced = True
            break
    if not replaced:
        exploits.append(entry)
    index_doc["exploitations"] = exploits
    write_index(scan_dir, index_doc)
    return entry


def append_commands_output(target_dir: str, step_results: list[dict]) -> str:
    """Write/append a human-readable command transcript under ``target_dir``."""
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "commands_output.txt")
    lines = []
    for step in step_results or []:
        if not isinstance(step, dict):
            continue
        title = step.get("title") or step.get("step") or step.get("action") or "step"
        cmd = step.get("command") or step.get("cmd") or ""
        summary = step.get("result_summary") or ""
        stdout = step.get("stdout") or step.get("output") or ""
        stderr = step.get("stderr") or ""
        lines.append(f"## {title}")
        if cmd:
            lines.append(f"$ {cmd}")
        if summary:
            lines.append(str(summary))
        if stdout:
            lines.append(str(stdout))
        if stderr:
            lines.append(f"[stderr]\n{stderr}")
        lines.append("")
    body = "\n".join(lines).rstrip() + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(body)
    # Also keep a scan-level aggregate for quick review.
    return path


def dual_write_tree(src_dir: str, dest_dir: str) -> None:
    """Copy files from src into dest (create dest). Skips if src missing."""
    if not src_dir or not os.path.isdir(src_dir):
        return
    os.makedirs(dest_dir, exist_ok=True)
    for name in os.listdir(src_dir):
        src = os.path.join(src_dir, name)
        dest = os.path.join(dest_dir, name)
        if os.path.isfile(src):
            shutil.copyfile(src, dest)


def resolve_scan_dir_from_metadata(metadata: dict | None, scans_root: str | None = None) -> str | None:
    """Return absolute scan dir from assessment metadata, if present and valid."""
    if not isinstance(metadata, dict):
        return None
    scan_id = str(metadata.get("scan_id") or "").strip()
    scan_dir = str(metadata.get("scan_dir") or "").strip()
    root = scans_root or default_scans_root()

    candidates = []
    if scan_dir:
        if os.path.isabs(scan_dir):
            candidates.append(scan_dir)
        else:
            candidates.append(os.path.join(project_root(), scan_dir))
            candidates.append(os.path.join(root, os.path.basename(scan_dir)))
    if scan_id and _SCAN_ID.fullmatch(scan_id):
        candidates.append(os.path.join(root, scan_id))

    for path in candidates:
        real = os.path.realpath(path)
        if os.path.isdir(real) and os.path.isfile(os.path.join(real, "index.json")):
            return real
    return None


def find_scan_dir_for_legacy_report(
    report_name: str,
    *,
    scans_root: str | None = None,
    legacy_reports_dir: str | None = None,
) -> str | None:
    """Locate a scan folder that owns a legacy security_report_* basename."""
    stamp = stamp_from_legacy_report_name(report_name)
    if not stamp:
        return None
    root = scans_root or default_scans_root()
    if os.path.isdir(root):
        for name in os.listdir(root):
            if not name.startswith(f"scan_{stamp}_"):
                continue
            scan_dir = os.path.join(root, name)
            if os.path.isfile(os.path.join(scan_dir, "index.json")):
                return os.path.realpath(scan_dir)
            if os.path.isfile(os.path.join(scan_dir, f"security_report_{stamp}.json")):
                return os.path.realpath(scan_dir)

    # Fallback: metadata inside flat dual-write JSON.
    legacy_root = legacy_reports_dir or default_legacy_reports_root()
    json_path = os.path.join(legacy_root, f"security_report_{stamp}.json")
    if os.path.isfile(json_path):
        try:
            with open(json_path, encoding="utf-8") as handle:
                data = json.load(handle)
            meta = data.get("metadata") if isinstance(data, dict) else None
            return resolve_scan_dir_from_metadata(meta, scans_root=root)
        except (OSError, json.JSONDecodeError, ValueError):
            return None
    return None
