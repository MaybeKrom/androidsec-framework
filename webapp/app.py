"""Local Flask UI for androidsec. The CLI in main.py is unchanged."""

import os
import re
import sys

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
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
from webapp.review import bp as review_bp  # noqa: E402

_REPORT_NAME = re.compile(r"security_report_\d{8}_\d{6}\.html$")

MAX_UPLOAD_BYTES = 256 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.secret_key = os.environ.get("ANDROIDSEC_SECRET", "androidsec-local")
app.register_blueprint(decompile_bp)
app.register_blueprint(device_bp)
app.register_blueprint(review_bp)


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
    return render_template("home.html")


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
        flash("Select at least one analyzer.")
        return redirect(url_for("assess"))

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
    return jsonify({
        "status": job["status"],
        "message": job["message"],
        "error": job["error"],
    })


def _send_report_file(filename):
    """Serve one HTML file from output_reports. The name is a basename, not a path."""
    if filename != "masvs_explanations.html" and not _REPORT_NAME.fullmatch(filename):
        abort(404)
    if filename != "masvs_explanations.html" and not is_live_report(filename):
        abort(404)
    path = os.path.join(REPORT_DIR, filename)
    if not _inside(path, REPORT_DIR) or not os.path.isfile(path):
        abort(404)
    return send_file(os.path.realpath(path), mimetype="text/html")


@app.get("/report/<job_id>")
def report(job_id):
    job = get_job(job_id)
    if not job:
        abort(404)
    if job["status"] != "done" or not job.get("html_path"):
        return redirect(url_for("scanning", job_id=job_id))
    # Redirect to the real filename so relative links to masvs_explanations.html resolve.
    return redirect(url_for("report_file", filename=os.path.basename(job["html_path"])))


@app.get("/reports/<filename>")
def report_file(filename):
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
