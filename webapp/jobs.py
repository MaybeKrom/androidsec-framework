"""In-memory scan jobs. One background thread per scan."""

import os
import threading
import uuid

_lock = threading.Lock()
_jobs = {}


_env_lock = threading.Lock()


def create_job(apk_path, analyzers, serial=None):
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "apk_path": apk_path,
        "apk_name": os.path.basename(apk_path),
        "analyzers": list(analyzers),
        "serial": serial or None,
        "status": "queued",
        "message": "Queued",
        "error": None,
        "html_path": None,
        "json_path": None,
        "summary": None,
    }
    with _lock:
        _jobs[job_id] = job
    threading.Thread(target=_run, args=(job_id,), daemon=True).start()
    return job_id


def get_job(job_id):
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def is_live_report(filename):
    with _lock:
        for job in _jobs.values():
            path = job.get("html_path")
            if path and os.path.basename(path) == filename:
                return True
    return False


def _update(job_id, **fields):
    with _lock:
        job = _jobs.get(job_id)
        if job:
            job.update(fields)


def _run(job_id):
    from main import run_scan

    job = get_job(job_id)
    if not job:
        return

    def on_progress(_tool_id, message):
        _update(job_id, status="running", message=message)

    serial = job.get("serial")
    held = False
    previous = None
    failed = False
    result = None
    _update(job_id, status="running", message="Starting scan…")
    try:
        if serial:
            from webapp.device import ready_serial
            if not ready_serial(serial):
                _update(
                    job_id,
                    status="error",
                    message="Device unavailable",
                    error="The selected device is no longer connected.",
                )
                failed = True
            else:
                # One dynamic scan at a time. ANDROID_SERIAL is process-wide,
                # and the dynamic analyzers call adb without their own serial.
                _env_lock.acquire()
                held = True
                previous = os.environ.get("ANDROID_SERIAL")
                os.environ["ANDROID_SERIAL"] = serial
        if not failed:
            result = run_scan(
                job["apk_path"],
                only=job["analyzers"],
                start_adb=False,
                on_progress=on_progress,
            )
    except Exception as exc:
        _update(
            job_id,
            status="error",
            message="Scan failed",
            error=f"{type(exc).__name__}: {exc}",
        )
        failed = True
    finally:
        if held:
            if previous is None:
                os.environ.pop("ANDROID_SERIAL", None)
            else:
                os.environ["ANDROID_SERIAL"] = previous
            _env_lock.release()

    if failed or result is None:
        return

    _update(
        job_id,
        status="done",
        message="Scan finished",
        error=None,
        html_path=result["html_path"],
        json_path=result["json_path"],
        summary=result["summary"],
    )
