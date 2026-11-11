"""Decode an APK with apktool, show the files, and rebuild it.

jadx is used when it is installed so the same page can show Java sources.
The CLI never imports this module.
"""

import os
import re
import shutil
import subprocess
import threading
import uuid
import zipfile

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, send_file, url_for

from webapp.apk_library import resolve_apk

try:
    from analyzers.utils import fmt_size
except ImportError:
    def fmt_size(num):
        return f"{num} B"

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
DECODED_DIR = os.path.join(WEB_DIR, "decoded")
_JOB_ID = re.compile(r"[0-9a-f]{12}")
_TEXT_EXT = {
    ".xml", ".smali", ".java", ".txt", ".json", ".yml", ".yaml", ".properties",
    ".html", ".js", ".css", ".md", ".mf", ".cfg", ".ini", ".csv", ".gradle",
    ".pro", ".kt", ".version", ".toml",
}
_PREVIEW_LIMIT = 200_000
_LIST_LIMIT = 500
_TIMEOUT = 300

bp = Blueprint("decompile", __name__)
_lock = threading.Lock()
_jobs = {}


def _which(name):
    return shutil.which(name)


def _update(job_id, **fields):
    with _lock:
        job = _jobs.get(job_id)
        if job:
            job.update(fields)


def get_decompile_job(job_id):
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _tail(text):
    lines = (text or "").strip().splitlines()
    body = "\n".join(lines[-40:])
    return body[-4000:]


def _run_tool(cmd):
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, "The tool ran longer than 5 minutes and was stopped."
    output = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    if proc.returncode != 0:
        return False, _tail(output) or f"The tool exited with status {proc.returncode}."
    return True, _tail(output)


def _work(job_id):
    job = get_decompile_job(job_id)
    if not job:
        return
    root = job["root"]
    apktool_dir = os.path.join(root, "apktool")
    jadx_dir = os.path.join(root, "jadx")
    try:
        _update(job_id, status="running", message="Decoding resources with apktool…")
        ok, detail = _run_tool(["apktool", "d", "-f", "-o", apktool_dir, job["apk_path"]])
        if not ok:
            _update(job_id, status="error", message="Decompile failed", error=detail)
            return

        jadx = _which("jadx")
        java_dir = ""
        jadx_error = ""
        if not jadx:
            jadx_error = "jadx is not installed, so Java sources were not created."
        else:
            _update(job_id, message="Decompiling Java with jadx…")
            ok, detail = _run_tool([jadx, "--no-res", "-d", jadx_dir, job["apk_path"]])
            sources = os.path.join(jadx_dir, "sources")
            if os.path.isdir(sources):
                java_dir = sources
            elif os.path.isdir(jadx_dir):
                java_dir = jadx_dir
            if not ok and not java_dir:
                jadx_error = detail or "jadx did not produce Java sources."
                java_dir = ""
            elif not ok:
                jadx_error = detail

        _update(
            job_id,
            status="done",
            message="Ready",
            error=None,
            apktool_dir=apktool_dir,
            java_dir=java_dir,
            jadx_error=jadx_error,
        )
    except Exception as exc:
        _update(
            job_id,
            status="error",
            message="Decompile failed",
            error=f"{type(exc).__name__}: {exc}",
        )


def start_decompile(apk_path):
    """Start apktool and jadx on a background thread. Returns the job id."""
    if not _which("apktool"):
        raise RuntimeError("apktool is not installed.")
    os.makedirs(DECODED_DIR, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    root = os.path.join(DECODED_DIR, job_id)
    os.makedirs(root, exist_ok=True)
    job = {
        "id": job_id,
        "apk_path": apk_path,
        "apk_name": os.path.basename(apk_path),
        "root": root,
        "status": "queued",
        "message": "Queued",
        "error": None,
        "apktool_dir": "",
        "java_dir": "",
        "jadx_error": "",
        "rebuild_status": "idle",
        "rebuild_error": "",
        "rebuild_path": "",
    }
    with _lock:
        _jobs[job_id] = job
    threading.Thread(target=_work, args=(job_id,), daemon=True).start()
    return job_id


def _prepare_apktool_meta(apktool_dir):
    """Drop the YAML type tag apktool 2.7 writes.

    The Debian build of apktool links a SnakeYAML that refuses that tag on
    the way back in, so rebuild never starts. The rest of the file is unchanged.
    """
    path = os.path.join(apktool_dir, "apktool.yml")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if text.startswith("!!"):
        newline = text.find("\n")
        body = text[newline + 1:] if newline != -1 else ""
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)


def _rebuild(job_id):
    job = get_decompile_job(job_id)
    if not job:
        return
    out = os.path.join(job["root"], "rebuilt.apk")
    try:
        _prepare_apktool_meta(job["apktool_dir"])
        cmd = ["apktool", "b", "-o", out, job["apktool_dir"]]
        if _which("aapt2"):
            cmd = ["apktool", "b", "--use-aapt2", "-o", out, job["apktool_dir"]]
        ok, detail = _run_tool(cmd)
        if not ok or not os.path.isfile(out):
            _update(job_id, rebuild_status="error", rebuild_error=detail or "apktool did not write an APK.")
            return
        _update(job_id, rebuild_status="done", rebuild_error="", rebuild_path=out)
    except Exception as exc:
        _update(job_id, rebuild_status="error", rebuild_error=f"{type(exc).__name__}: {exc}")


def _tree_root(job, tree):
    if tree == "apktool":
        return job.get("apktool_dir") or ""
    if tree == "jadx":
        return job.get("java_dir") or ""
    return ""


def resolve_inside(root, rel_path):
    """Resolve a relative path and refuse anything outside root."""
    if not root or not os.path.isdir(root):
        return None
    rel_path = (rel_path or "").replace("\\", "/").strip()
    if rel_path.startswith("/"):
        return None
    root_real = os.path.realpath(root)
    target = root_real
    for part in rel_path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        nxt = os.path.join(target, part)
        if os.path.islink(nxt):
            return None
        target = os.path.realpath(nxt)
        if target != root_real and not target.startswith(root_real + os.sep):
            return None
    if not os.path.exists(target):
        return None
    return target


def _crumbs(rel_path):
    crumbs = [{"name": "Root", "path": ""}]
    acc = []
    for part in (rel_path or "").split("/"):
        if not part:
            continue
        acc.append(part)
        crumbs.append({"name": part, "path": "/".join(acc)})
    return crumbs


def _looks_text(path):
    try:
        with open(path, "rb") as handle:
            sample = handle.read(4096)
    except OSError:
        return False
    if not sample or b"\0" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def read_preview(path):
    ext = os.path.splitext(path)[1].lower()
    if ext not in _TEXT_EXT and not _looks_text(path):
        return None, False
    try:
        with open(path, "rb") as handle:
            data = handle.read(_PREVIEW_LIMIT + 1)
    except OSError:
        return None, False
    if b"\0" in data[:4096]:
        return None, False
    clipped = len(data) > _PREVIEW_LIMIT
    return data[:_PREVIEW_LIMIT].decode("utf-8", errors="replace"), clipped


def list_directory(root, rel_path):
    path = resolve_inside(root, rel_path)
    if path is None or not os.path.isdir(path):
        return None
    names = sorted(os.listdir(path), key=lambda name: (not os.path.isdir(os.path.join(path, name)), name.lower()))
    entries = []
    for name in names:
        full = os.path.join(path, name)
        if os.path.islink(full):
            continue
        rel = name if not rel_path else rel_path.rstrip("/") + "/" + name
        is_dir = os.path.isdir(full)
        entries.append({
            "name": name,
            "path": rel,
            "is_dir": is_dir,
            "size": "" if is_dir else fmt_size(os.path.getsize(full)),
        })
    truncated = len(entries) > _LIST_LIMIT
    return entries[:_LIST_LIMIT], truncated


def make_archive(root, dest):
    if os.path.isfile(dest):
        return dest
    tmp = dest + ".part"
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if not os.path.islink(os.path.join(dirpath, name))]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue
                arc = os.path.relpath(full, root)
                if arc.startswith(".."):
                    continue
                archive.write(full, arc)
    os.replace(tmp, dest)
    return dest


def _job_or_404(job_id):
    if not _JOB_ID.fullmatch(job_id or ""):
        abort(404)
    job = get_decompile_job(job_id)
    if not job:
        abort(404)
    return job


@bp.post("/decompile")
def start():
    apk_path = resolve_apk(request.form.get("apk", ""))
    if not apk_path:
        flash("Select an APK from the list.", "error")
        return redirect(url_for("assess"))
    try:
        job_id = start_decompile(apk_path)
    except RuntimeError as exc:
        flash(str(exc), "error")
        return redirect(url_for("assess"))
    return redirect(url_for("decompile.page", job_id=job_id))


@bp.get("/decompile/<job_id>")
def page(job_id):
    job = _job_or_404(job_id)
    tree = request.args.get("tree", "apktool")
    if tree not in ("apktool", "jadx"):
        tree = "apktool"
    rel = (request.args.get("path") or "").replace("\\", "/").strip("/")
    entries = []
    truncated = False
    preview = None
    clipped = False
    viewing = None
    parent = ""
    if job["status"] == "done":
        root = _tree_root(job, tree)
        target = resolve_inside(root, rel) if root else None
        if target is None:
            rel = ""
            target = resolve_inside(root, "") if root else None
        if target and os.path.isfile(target):
            viewing = os.path.basename(target)
            preview, clipped = read_preview(target)
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
        elif target and os.path.isdir(target):
            listed = list_directory(root, rel)
            if listed:
                entries, truncated = listed
            if rel:
                parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
    return render_template(
        "decompile.html",
        job=job,
        tree=tree,
        rel=rel,
        entries=entries,
        truncated=truncated,
        preview=preview,
        clipped=clipped,
        viewing=viewing,
        parent=parent,
        crumbs=_crumbs(rel),
    )


@bp.get("/decompile/<job_id>/status")
def status(job_id):
    job = _job_or_404(job_id)
    return jsonify({
        "status": job["status"],
        "message": job["message"],
        "error": job["error"],
        "rebuild_status": job["rebuild_status"],
        "rebuild_error": job["rebuild_error"],
    })


@bp.get("/decompile/<job_id>/download")
def download(job_id):
    job = _job_or_404(job_id)
    if job["status"] != "done":
        abort(404)
    tree = request.args.get("tree", "apktool")
    root = _tree_root(job, tree)
    target = resolve_inside(root, request.args.get("path", ""))
    if target is None or not os.path.isfile(target):
        abort(404)
    return send_file(target, as_attachment=True, download_name=os.path.basename(target))


@bp.get("/decompile/<job_id>/archive")
def archive(job_id):
    job = _job_or_404(job_id)
    if job["status"] != "done":
        abort(404)
    tree = request.args.get("tree", "apktool")
    root = _tree_root(job, tree)
    if not root or not os.path.isdir(root):
        abort(404)
    dest = os.path.join(job["root"], f"{tree}.zip")
    try:
        make_archive(root, dest)
    except OSError:
        abort(404)
    name = f"{os.path.splitext(job['apk_name'])[0]}-{tree}.zip"
    return send_file(dest, as_attachment=True, download_name=name)


@bp.post("/decompile/<job_id>/rebuild")
def rebuild(job_id):
    job = _job_or_404(job_id)
    if job["status"] != "done" or not job.get("apktool_dir"):
        flash("Decompile the APK before rebuilding it.", "error")
        return redirect(url_for("decompile.page", job_id=job_id))
    if job["rebuild_status"] != "running":
        _update(job_id, rebuild_status="running", rebuild_error="")
        threading.Thread(target=_rebuild, args=(job_id,), daemon=True).start()
    return redirect(url_for("decompile.page", job_id=job_id))


@bp.get("/decompile/<job_id>/rebuilt")
def rebuilt(job_id):
    job = _job_or_404(job_id)
    path = job.get("rebuild_path") or ""
    root = os.path.realpath(job["root"])
    if not path or os.path.realpath(path) != os.path.join(root, "rebuilt.apk") or not os.path.isfile(path):
        abort(404)
    stem = os.path.splitext(job["apk_name"])[0]
    return send_file(path, as_attachment=True, download_name=f"{stem}-rebuilt.apk")
