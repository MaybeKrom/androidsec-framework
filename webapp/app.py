"""Local Flask UI for androidsec. The CLI in main.py is unchanged."""

import os
import re
import sys

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(WEB_DIR)
UPLOAD_DIR = os.path.join(WEB_DIR, "uploads")
REPORT_DIR = os.path.join(PROJECT_ROOT, "output_reports")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import main as scan_main  # noqa: E402
from webapp.apk_library import delete_upload, list_apks, resolve_apk, save_upload  # noqa: E402
from webapp.decompile import DECODED_DIR, bp as decompile_bp  # noqa: E402
from webapp.device import bp as device_bp  # noqa: E402
from webapp.device import ready_serial, valid_serial  # noqa: E402
from webapp.jobs import create_job, get_job, is_live_report  # noqa: E402
from webapp.exploit import bp as exploit_bp  # noqa: E402

_REPORT_NAME = re.compile(r"security_report_\d{8}_\d{6}\.html$")
_REPORT_PDF = re.compile(r"security_report_\d{8}_\d{6}\.pdf$")

MAX_UPLOAD_BYTES = 256 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.secret_key = os.environ.get("ANDROIDSEC_SECRET", "androidsec-local")
app.register_blueprint(decompile_bp)
app.register_blueprint(device_bp)
app.register_blueprint(exploit_bp)


def _inside(path, directory):
    real = os.path.realpath(path)
    root = os.path.realpath(directory)
    return real == root or real.startswith(root + os.sep)


def analyzer_groups():
    static, dynamic = [], []
    for tool_id, _mod, desc in scan_main.ANALYZERS:
        row = {"id": tool_id, "description": desc}
        if tool_id in scan_main.DYNAMIC_ANALYZERS:
            dynamic.append(row)
        else:
            static.append(row)
    return static, dynamic


@app.get("/")
def home():
    static, dynamic = analyzer_groups()
    return render_template(
        "home.html",
        tool_count=len(static) + len(dynamic),
        static_count=len(static),
        dynamic_count=len(dynamic),
    )


@app.get("/assess")
def assess():
    static, dynamic = analyzer_groups()
    apks = list_apks()
    selected = request.args.get("selected", "")
    keys = {apk["key"] for apk in apks}
    if selected not in keys:
        selected = apks[0]["key"] if apks else ""
    return render_template(
        "assess.html",
        apks=apks,
        selected=selected,
        static_analyzers=static,
        dynamic_analyzers=dynamic,
    )


@app.get("/assess/analyzers")
def analyzers():
    key = request.args.get("apk", "")
    chosen = next((apk for apk in list_apks() if apk["key"] == key), None)
    if not chosen:
        flash("Select an APK from the list.", "error")
        return redirect(url_for("assess"))
    static, dynamic = analyzer_groups()
    return render_template(
        "analyzers.html",
        apk=chosen,
        static_analyzers=static,
        dynamic_analyzers=dynamic,
    )


@app.post("/upload")
def upload():
    uploaded = request.files.get("apk")
    if uploaded is None or not uploaded.filename:
        flash("Choose an APK file to upload.", "error")
        return redirect(url_for("assess"))

    filename = secure_filename(uploaded.filename)
    if not filename.lower().endswith(".apk"):
        flash("Upload a file whose name ends in .apk.", "error")
        return redirect(url_for("assess"))

    try:
        dest_name = save_upload(uploaded, filename)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("assess"))

    flash(f"Uploaded {dest_name}.")
    return redirect(url_for("assess", selected=f"upload:{dest_name}"))


@app.post("/apks/delete")
def delete_apk():
    ok, message = delete_upload(request.form.get("apk", ""))
    flash(message, "ok" if ok else "error")
    return redirect(url_for("assess"))


@app.post("/scan")
def start_scan():
    apk_path = resolve_apk(request.form.get("apk", ""))
    if not apk_path:
        flash("Select an APK from the list.")
        return redirect(url_for("assess"))

    known = {tool_id for tool_id, _mod, _desc in scan_main.ANALYZERS}
    chosen = {name for name in request.form.getlist("analyzers") if name in known}
    ordered = [tool_id for tool_id, _mod, _desc in scan_main.ANALYZERS if tool_id in chosen]
    if not ordered:
        flash("Select at least one analyzer.", "error")
        return redirect(url_for("analyzers", apk=request.form.get("apk", "")))

    dynamic = [tool_id for tool_id in ordered if tool_id in scan_main.DYNAMIC_ANALYZERS]
    serial = (request.form.get("serial") or "").strip()
    if dynamic:
        allowed = (
            request.form.get("authorized") == "yes"
            and valid_serial(serial)
            and ready_serial(serial)
        )
        if not allowed:
            session["pending_scan"] = {
                "apk": request.form.get("apk", ""),
                "analyzers": ordered,
            }
            if request.form.get("authorized") != "yes":
                flash("Dynamic checks need a device and your authorization.", "error")
            else:
                flash("Choose a connected device before running dynamic checks.", "error")
            return redirect(url_for("device.page", serial=serial, apk=request.form.get("apk", "")))
        session.pop("pending_scan", None)
        job_id = create_job(apk_path, ordered, serial=serial)
    else:
        session.pop("pending_scan", None)
        job_id = create_job(apk_path, ordered)
    return redirect(url_for("scanning", job_id=job_id))


@app.get("/scan/<job_id>")
def scanning(job_id):
    job = get_job(job_id)
    if not job:
        abort(404)
    return render_template("scanning.html", job=job)


@app.get("/scan/<job_id>/status")
def scan_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Scan not found", "error": "Scan not found"}), 404
    total = job.get("total") or 0
    completed = job.get("completed") or 0
    if job["status"] == "done":
        percent = 100
    elif total:
        percent = int(completed * 100 / total)
    else:
        percent = 0
    return jsonify({
        "status": job["status"],
        "message": job["message"],
        "error": job["error"],
        "steps": job.get("steps") or [],
        "completed": completed,
        "total": total,
        "percent": percent,
    })


def _report_path(filename):
    """Return a report path inside output_reports, or abort."""
    path = os.path.join(REPORT_DIR, filename)
    if not _inside(path, REPORT_DIR) or not os.path.isfile(path):
        abort(404)
    return os.path.realpath(path)


def _pdf_bar(pdf_name):
    return (
        '<div id="androsec-pdf" style="position:sticky;top:0;z-index:30;display:flex;'
        'justify-content:space-between;align-items:center;gap:12px;padding:12px 18px;'
        'background:#070B14;color:#F5F8FF;font-family:ui-sans-serif,Segoe UI,sans-serif;">'
        '<strong style="letter-spacing:-0.03em">andro<span style="color:#B8FF30">sec</span></strong>'
        f'<a href="{escape(pdf_name)}" style="display:inline-flex;align-items:center;'
        'padding:8px 14px;border:1px solid #B8FF30;border-radius:10px;color:#B8FF30;'
        'font-weight:700;text-decoration:none;background:#0A1020;">Download PDF</a></div>'
    )


def _send_report_file(filename):
    """Serve one HTML file from output_reports. The name is a basename, not a path."""
    if filename != "masvs_explanations.html" and not _REPORT_NAME.fullmatch(filename):
        abort(404)
    if filename != "masvs_explanations.html" and not is_live_report(filename):
        abort(404)
    path = _report_path(filename)
    if filename == "masvs_explanations.html":
        return send_file(path, mimetype="text/html")
    with open(path, encoding="utf-8") as handle:
        html = handle.read()
    html = html.replace("<th>Title</th>", "<th>Vulnerability</th>", 1)
    html = html.replace("<body>", "<body>" + _pdf_bar(filename[:-5] + ".pdf"), 1)
    return Response(html, mimetype="text/html; charset=utf-8")


def _send_report_pdf(filename):
    if not _REPORT_PDF.fullmatch(filename):
        abort(404)
    html_name = filename[:-4] + ".html"
    if not is_live_report(html_name):
        abort(404)
    html_path = _report_path(html_name)
    pdf_path = os.path.join(REPORT_DIR, filename)
    if not _inside(pdf_path, REPORT_DIR):
        abort(404)
    json_path = os.path.join(REPORT_DIR, html_name[:-5] + ".json")
    if not _inside(json_path, REPORT_DIR) or not os.path.isfile(json_path):
        page = "<!DOCTYPE html><title>PDF unavailable</title><p>The JSON report next to this HTML file is missing, so the PDF cannot be built.</p>"
        return Response(page, status=404, mimetype="text/html; charset=utf-8")
    try:
        import json
        from reporter.report_generator import ReportGenerator
        with open(json_path, encoding="utf-8") as handle:
            data = json.load(handle)
        ReportGenerator(
            data.get("metadata") or {},
            data.get("tool_outputs") or [],
            data.get("findings") or [],
            data.get("summary") or {},
        ).save_pdf(pdf_path)
    except ImportError:
        page = "<!DOCTYPE html><title>PDF unavailable</title><p>Install weasyprint to download this report as PDF.</p>"
        return Response(page, status=503, mimetype="text/html; charset=utf-8")
    except Exception as exc:
        page = f"<!DOCTYPE html><title>PDF failed</title><p>Could not build the PDF. {escape(exc)}</p>"
        return Response(page, status=500, mimetype="text/html; charset=utf-8")
    return send_file(
        os.path.realpath(pdf_path),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.get("/report/<job_id>")
def report(job_id):
    job = get_job(job_id)
    if not job:
        abort(404)
    if job["status"] != "done" or not job.get("html_path"):
        return redirect(url_for("scanning", job_id=job_id))
    return redirect(url_for("report_file", filename=os.path.basename(job["html_path"])))


@app.get("/reports/<filename>")
def report_file(filename):
    if filename.endswith(".pdf"):
        return _send_report_pdf(filename)
    return _send_report_file(filename)


@app.errorhandler(413)
def too_large(_exc):
    flash("That file is larger than 256 MB.")
    return redirect(url_for("assess"))


def main():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(DECODED_DIR, exist_ok=True)
    app.run(host="127.0.0.1", port=5000, threaded=True)


if __name__ == "__main__":
    main()
