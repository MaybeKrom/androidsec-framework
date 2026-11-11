"""Device step for the local web UI.

Every adb command is a fixed argument list: list, connect, disconnect,
getprop, pm path, install, id, and a root check. Serials and IP addresses
are checked before they are passed through. There is no free-form shell.
"""

import ipaddress
import re
import shutil
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, session, url_for

from webapp.apk_library import describe, list_apks, resolve_apk

bp = Blueprint("device", __name__)

AUTH_TEXT = "I confirm I am fully authorized to test this device and application."

_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
_PACKAGE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
_JOB_ID = re.compile(r"[0-9a-f]{12}")

_CONNECT_TIMEOUT = 15
_INSTALL_TIMEOUT = 120
_ROOT_TIMEOUT = 30
_SHELL_TIMEOUT = 8

_lock = threading.Lock()
_jobs = {}


class AdbError(Exception):
    pass


def adb_path():
    return shutil.which("adb")


def valid_serial(serial):
    return bool(serial) and bool(_SERIAL.fullmatch(serial))


def valid_package(name):
    return bool(name) and len(name) <= 200 and bool(_PACKAGE.fullmatch(name))


def parse_endpoint(host_text, port_text):
    """Return (ipv4, port). Raises ValueError with a message safe to show."""
    host_text = (host_text or "").strip()
    port_text = "" if port_text is None else str(port_text).strip()
    if not host_text:
        raise ValueError("Enter an IP address.")
    if host_text.count(":") > 1 or "/" in host_text or " " in host_text:
        raise ValueError("Enter an IPv4 address, with the port in the port field.")
    if ":" in host_text:
        if port_text:
            raise ValueError("Put the port in the port field, not in the address.")
        host_text, _, port_text = host_text.partition(":")
        if not port_text:
            port_text = "5555"
    try:
        ip = str(ipaddress.IPv4Address(host_text))
    except ipaddress.AddressValueError:
        raise ValueError("Enter a valid IPv4 address.") from None
    if not port_text:
        port = 5555
    elif port_text.isdigit():
        port = int(port_text)
    else:
        raise ValueError("The port must be a number from 1 to 65535.")
    if not 1 <= port <= 65535:
        raise ValueError("The port must be a number from 1 to 65535.")
    target = f"{ip}:{port}"
    if not valid_serial(target):
        raise ValueError("That address cannot be used as a device serial.")
    return ip, port


def parse_devices(text):
    """Turn `adb devices -l` output into a list of device dicts."""
    devices = []
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("List of devices") or raw.startswith("*"):
            continue
        parts = raw.split()
        if len(parts) < 2 or not valid_serial(parts[0]):
            continue
        if parts[1] == "no" and len(parts) > 2 and parts[2] == "permissions":
            state = "no permissions"
            extra = parts[3:]
        else:
            state = parts[1]
            extra = parts[2:]
        model = ""
        for token in extra:
            if token.startswith("model:"):
                model = token.split(":", 1)[1].replace("_", " ")
        devices.append({
            "serial": parts[0],
            "state": state,
            "model": model,
            "ready": state == "device",
            "label": _state_label(state),
            "pill": _state_pill(state),
        })
    return devices


def _state_label(state):
    return {
        "device": "Ready",
        "unauthorized": "Unauthorized",
        "offline": "Offline",
        "no permissions": "No permissions",
    }.get(state, state)


def _state_pill(state):
    if state == "device":
        return "ready"
    if state in ("unauthorized", "no permissions"):
        return "wait"
    return "down"


def _plain(text, limit, keep="tail"):
    cleaned = "".join(ch for ch in (text or "") if ch.isprintable() or ch in "\n\t")
    cleaned = cleaned.strip()
    if len(cleaned) <= limit:
        return cleaned
    if keep == "head":
        return cleaned[:limit].rstrip() + "…"
    return cleaned[-limit:]


def run_adb(args, timeout):
    binary = adb_path()
    if not binary:
        raise AdbError("adb is not installed or not on PATH.")
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdbError(f"adb timed out after {timeout} seconds.") from exc
    except OSError as exc:
        raise AdbError(f"adb could not be started: {exc}") from exc
    output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
    return proc.returncode, output


def list_devices():
    if not adb_path():
        return {
            "available": False,
            "error": "adb is not installed or not on PATH.",
            "devices": [],
        }
    try:
        code, output = run_adb(["devices", "-l"], timeout=_SHELL_TIMEOUT)
    except AdbError as exc:
        return {"available": True, "error": str(exc), "devices": []}
    devices = parse_devices(output)
    error = None
    if code != 0 and not devices:
        error = _plain(output, 500) or "adb devices failed."
    return {"available": True, "error": error, "devices": devices}


def ready_serial(serial):
    if not valid_serial(serial):
        return False
    listing = list_devices()
    return any(item["serial"] == serial and item["ready"] for item in listing["devices"])


def package_for(apk_key):
    path = resolve_apk(apk_key or "")
    if not path or not apk_key or apk_key.count(":") != 1:
        return None, ""
    kind, name = apk_key.split(":", 1)
    info = describe(kind, name, path)
    package = info.get("package") or ""
    if not valid_package(package):
        return path, ""
    return path, package


def install_status(serial, package):
    if not valid_serial(serial) or not valid_package(package):
        return {"installed": False, "path": "", "error": "Package name is not available."}
    try:
        _code, output = run_adb(
            ["-s", serial, "shell", "pm", "path", package],
            timeout=_SHELL_TIMEOUT,
        )
    except AdbError as exc:
        return {"installed": False, "path": "", "error": str(exc)}
    for line in output.splitlines():
        if line.strip().startswith("package:"):
            return {"installed": True, "path": line.strip(), "error": None}
    return {"installed": False, "path": "", "error": None}


def device_facts(serial):
    wanted = (
        ("ro.product.manufacturer", "Manufacturer"),
        ("ro.product.model", "Model"),
        ("ro.build.version.release", "Android"),
        ("ro.build.version.sdk", "SDK"),
    )
    try:
        _code, output = run_adb(["-s", serial, "shell", "getprop"], timeout=_SHELL_TIMEOUT)
    except AdbError as exc:
        return {"facts": [], "error": str(exc)}
    found = {}
    for line in output.splitlines():
        if not line.startswith("[") or "]: [" not in line:
            continue
        key, value = line[1:].split("]: [", 1)
        if value.endswith("]"):
            value = value[:-1]
        found[key] = _plain(value, 80, keep="head").replace("\n", " ")
    facts = [
        {"label": label, "value": found[key]}
        for key, label in wanted
        if found.get(key)
    ]
    return {"facts": facts, "error": None}


def shell_identity(serial):
    try:
        _code, output = run_adb(["-s", serial, "shell", "id"], timeout=_SHELL_TIMEOUT)
    except AdbError as exc:
        return str(exc)
    line = output.splitlines()[0] if output else ""
    match = re.search(r"uid=\d+\([^)\s]*\)", line) or re.search(r"uid=\d+", line)
    if match:
        return match.group(0)
    return _plain(line, 160, keep="head").replace("\n", " ") or "No identity returned."


def perform_connect(ip, port):
    target = f"{ip}:{port}"
    try:
        _code, output = run_adb(["connect", target], timeout=_CONNECT_TIMEOUT)
    except AdbError as exc:
        if "timed out" in str(exc).lower():
            return False, f"Connecting to {target} timed out after {_CONNECT_TIMEOUT} seconds."
        return False, str(exc)
    lowered = output.lower()
    shown = _plain(output, 500) or f"No response from {target}."
    if "connected to" in lowered or "already connected" in lowered:
        return True, shown
    return False, shown


def perform_disconnect(serial):
    try:
        code, output = run_adb(["disconnect", serial], timeout=_SHELL_TIMEOUT)
    except AdbError as exc:
        return False, str(exc)
    shown = _plain(output, 500) or f"Disconnected {serial}."
    return code == 0, shown


def perform_install(serial, apk_key):
    path, package = package_for(apk_key)
    if not path:
        return False, "Select an APK from the list."
    if not package:
        return False, "That APK has no package name, so it was not installed."
    status = install_status(serial, package)
    if status["error"]:
        return False, status["error"]
    if status["installed"]:
        return True, f"{package} is already installed ({status['path']})."
    try:
        code, output = run_adb(
            ["-s", serial, "install", "-r", path],
            timeout=_INSTALL_TIMEOUT,
        )
    except AdbError as exc:
        if "timed out" in str(exc).lower():
            return False, (
                "Install timed out after 2 minutes. If the device is waiting "
                "for a confirmation, accept it and try again."
            )
        return False, str(exc)
    if code == 0:
        return True, f"Installed {package}."
    detail = _plain(output, 800) or "Install failed."
    return False, detail


def perform_root(serial):
    try:
        _code, identity = run_adb(["-s", serial, "shell", "id"], timeout=_SHELL_TIMEOUT)
    except AdbError as exc:
        return False, str(exc)
    if "uid=0" in identity:
        return True, "This device shell is already root (uid=0)."

    root_out = ""
    try:
        _code, root_out = run_adb(["-s", serial, "root"], timeout=_ROOT_TIMEOUT)
    except AdbError as exc:
        root_out = str(exc)

    lowered = root_out.lower()
    if "restarting adbd as root" in lowered or "already running as root" in lowered:
        try:
            run_adb(["-s", serial, "wait-for-device"], timeout=_ROOT_TIMEOUT)
            _code, identity = run_adb(["-s", serial, "shell", "id"], timeout=_SHELL_TIMEOUT)
        except AdbError as exc:
            return False, (
                "adb root restarted the daemon, then the device did not come back in time. "
                + str(exc)
            )
        if "uid=0" in identity:
            return True, "Root is available. adbd is running as root."

    try:
        _code, su_out = run_adb(
            ["-s", serial, "shell", "su", "-c", "id"],
            timeout=_ROOT_TIMEOUT,
        )
    except AdbError as exc:
        if "timed out" in str(exc).lower():
            return False, (
                "Timed out waiting for root approval on the device. "
                "Unlock it, accept the prompt, and try again."
            )
        return False, str(exc)
    if "uid=0" in su_out:
        return True, "Root approval granted (uid=0)."
    detail = _plain(su_out or root_out, 500)
    if "production builds" in lowered:
        return False, (
            "This Android build does not allow adbd as root, and su did not grant uid=0. "
            + detail
        )
    return False, "Root was not granted. " + (detail or "The device did not return uid=0.")


def _start_action(kind, message, serial, apk, work):
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "kind": kind,
        "serial": serial or "",
        "apk": apk or "",
        "status": "running",
        "message": message,
        "error": None,
    }
    with _lock:
        _jobs[job_id] = job

    def _thread():
        try:
            ok, result = work()
        except Exception as exc:
            ok, result = False, f"{type(exc).__name__}: {exc}"
        result = _plain(result, 1200) or ("Finished." if ok else "The action failed.")
        with _lock:
            current = _jobs.get(job_id)
            if not current:
                return
            current["status"] = "done" if ok else "error"
            current["message"] = result
            current["error"] = None if ok else result

    threading.Thread(target=_thread, daemon=True).start()
    return job_id


def get_action(job_id):
    if not job_id or not _JOB_ID.fullmatch(job_id):
        return None
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _apk_rows():
    rows = []
    for item in list_apks():
        path = resolve_apk(item["key"])
        package = ""
        if path and item["key"].count(":") == 1:
            kind, name = item["key"].split(":", 1)
            info = describe(kind, name, path)
            if valid_package(info.get("package") or ""):
                package = info["package"]
        row = dict(item)
        row["package"] = package
        rows.append(row)
    return rows


def _pending():
    raw = session.get("pending_scan")
    if not isinstance(raw, dict):
        return None
    apk = raw.get("apk")
    analyzers = raw.get("analyzers")
    if not isinstance(apk, str) or not isinstance(analyzers, list):
        return None
    names = [name for name in analyzers if isinstance(name, str) and name]
    if not apk or not names:
        return None
    return {"apk": apk, "analyzers": names}


def _authorized():
    if request.form.get("authorized") != "yes":
        flash(
            "Check the authorization box before connecting, installing, requesting root, or starting a dynamic scan.",
            "error",
        )
        return False
    return True


def _back():
    return redirect(url_for(
        "device.page",
        serial=request.form.get("serial", ""),
        apk=request.form.get("apk", ""),
    ))


def _ready_from_form():
    serial = (request.form.get("serial") or "").strip()
    if not valid_serial(serial):
        flash("Choose a device from the list.", "error")
        return None
    if not ready_serial(serial):
        flash("That device is not connected and ready. Unlock it and accept USB debugging if asked.", "error")
        return None
    return serial


@bp.get("/device")
def page():
    listing = list_devices()
    devices = listing["devices"]
    apks = _apk_rows()
    pending = _pending()
    keys = {item["key"] for item in apks}
    selected_apk = request.args.get("apk") or (pending["apk"] if pending else "")
    if selected_apk not in keys:
        selected_apk = apks[0]["key"] if apks else ""
    requested = (request.args.get("serial") or "").strip()
    ready = [item for item in devices if item["ready"]]
    if any(item["serial"] == requested and item["ready"] for item in devices):
        selected = requested
    else:
        selected = ready[0]["serial"] if ready else ""

    facts = []
    facts_error = ""
    identity = ""
    install = None
    package = ""
    if selected:
        package = next((item["package"] for item in apks if item["key"] == selected_apk), "")
        with ThreadPoolExecutor(max_workers=3) as pool:
            facts_call = pool.submit(device_facts, selected)
            identity_call = pool.submit(shell_identity, selected)
            install_call = pool.submit(install_status, selected, package) if package else None
            fact_result = facts_call.result()
            identity = identity_call.result()
            install = install_call.result() if install_call else None
        facts = fact_result["facts"]
        facts_error = fact_result["error"] or ""

    return render_template(
        "device.html",
        adb_available=listing["available"],
        adb_error=listing["error"],
        devices=devices,
        has_ready=bool(ready),
        selected=selected,
        apks=apks,
        selected_apk=selected_apk,
        package=package,
        facts=facts,
        facts_error=facts_error,
        identity=identity,
        install=install,
        pending=pending,
        auth_text=AUTH_TEXT,
    )


@bp.post("/device/connect")
def connect():
    if not _authorized():
        return _back()
    try:
        ip, port = parse_endpoint(request.form.get("host"), request.form.get("port"))
    except ValueError as exc:
        flash(str(exc), "error")
        return _back()
    serial = f"{ip}:{port}"
    apk = request.form.get("apk", "")
    job_id = _start_action(
        "connect",
        f"Connecting to {serial}. This stops after {_CONNECT_TIMEOUT} seconds if it does not answer.",
        serial,
        apk,
        lambda: perform_connect(ip, port),
    )
    return redirect(url_for("device.wait", job_id=job_id))


@bp.post("/device/disconnect")
def disconnect():
    if not _authorized():
        return _back()
    serial = (request.form.get("serial") or "").strip()
    if not valid_serial(serial) or ":" not in serial:
        flash("Disconnect is only for a device you connected by IP.", "error")
        return _back()
    ok, message = perform_disconnect(serial)
    flash(message, "ok" if ok else "error")
    return redirect(url_for("device.page", apk=request.form.get("apk", "")))


@bp.post("/device/install")
def install():
    if not _authorized():
        return _back()
    serial = _ready_from_form()
    if not serial:
        return _back()
    apk = request.form.get("apk", "")
    if not resolve_apk(apk):
        flash("Select an APK from the list.", "error")
        return _back()
    job_id = _start_action(
        "install",
        "Installing. Accept the confirmation on the device if it appears. This stops after 2 minutes.",
        serial,
        apk,
        lambda: perform_install(serial, apk),
    )
    return redirect(url_for("device.wait", job_id=job_id))


@bp.post("/device/root")
def root():
    if not _authorized():
        return _back()
    serial = _ready_from_form()
    if not serial:
        return _back()
    apk = request.form.get("apk", "")
    job_id = _start_action(
        "root",
        "Requesting root. Accept the prompt on the device if it appears. This stops after 30 seconds.",
        serial,
        apk,
        lambda: perform_root(serial),
    )
    return redirect(url_for("device.wait", job_id=job_id))


@bp.post("/device/cancel")
def cancel():
    session.pop("pending_scan", None)
    return redirect(url_for("assess"))


@bp.get("/device/wait/<job_id>")
def wait(job_id):
    job = get_action(job_id)
    if not job:
        abort(404)
    if job["status"] != "running":
        flash(job["message"], "ok" if job["status"] == "done" else "error")
        return redirect(url_for("device.page", serial=job.get("serial") or "", apk=job.get("apk") or ""))
    return render_template("device_wait.html", job=job)


@bp.get("/device/wait/<job_id>/status")
def wait_status(job_id):
    job = get_action(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Action not found", "error": "Action not found"}), 404
    return jsonify({
        "status": job["status"],
        "message": job["message"],
        "error": job["error"],
    })
