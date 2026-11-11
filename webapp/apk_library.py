"""Validate, describe, and delete APKs for the web UI.

The scan path still lives in main.run_scan. This module only answers
what an APK is and which uploaded files the user may remove.
"""

import json
import os
import sys

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(WEB_DIR)
UPLOAD_DIR = os.path.join(WEB_DIR, "uploads")
META_DIR = os.path.join(WEB_DIR, "meta")

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzers.utils import fmt_size

try:
    from loguru import logger
    logger.disable("androguard")
except ImportError:
    pass


def _inside(path, directory):
    real = os.path.realpath(path)
    root = os.path.realpath(directory)
    return real == root or real.startswith(root + os.sep)


def resolve_apk(choice):
    """Map a form value to an APK in the project root or the upload folder.

    The value must be ``root:<file>`` or ``upload:<file>`` with no path
    separators. A name such as ``../../something.apk`` is rejected.
    """
    if not choice or choice.count(":") != 1:
        return None
    kind, name = choice.split(":", 1)
    if not name or name != os.path.basename(name) or not name.lower().endswith(".apk"):
        return None
    if kind == "root":
        folder = PROJECT_ROOT
    elif kind == "upload":
        folder = UPLOAD_DIR
    else:
        return None
    path = os.path.join(folder, name)
    if os.path.isfile(path) and _inside(path, folder):
        return path
    return None


def _cache_path(kind, name):
    return os.path.join(META_DIR, f"{kind}__{name}.json")


def _stamp(path):
    st = os.stat(path)
    return {"size_bytes": st.st_size, "mtime_ns": st.st_mtime_ns}


def _read_apk(path):
    """Parse the manifest. A failure means the file is not a usable APK."""
    try:
        from androguard.core.apk import APK
        apk = APK(path)
        if not apk.is_valid_APK():
            return {"valid": False, "package": "", "app_name": "", "version": ""}
        package = apk.get_package() or ""
        try:
            app_name = apk.get_app_name() or package
        except Exception:
            app_name = package
        try:
            version = apk.get_androidversion_name() or ""
        except Exception:
            version = ""
        if not package:
            return {"valid": False, "package": "", "app_name": "", "version": ""}
        return {
            "valid": True,
            "package": str(package),
            "app_name": str(app_name or package),
            "version": str(version or ""),
        }
    except Exception:
        return {"valid": False, "package": "", "app_name": "", "version": ""}


def _load_cache(kind, name, path):
    cache = _cache_path(kind, name)
    if not os.path.isfile(cache):
        return None
    try:
        with open(cache, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    stamp = _stamp(path)
    if data.get("size_bytes") != stamp["size_bytes"] or data.get("mtime_ns") != stamp["mtime_ns"]:
        return None
    return data


def _write_cache(kind, name, path, info):
    os.makedirs(META_DIR, exist_ok=True)
    payload = dict(info)
    payload.update(_stamp(path))
    cache = _cache_path(kind, name)
    tmp = cache + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    os.replace(tmp, cache)


def describe(kind, name, path):
    """Package, version, and size. Reads the cache when the file has not changed."""
    cached = _load_cache(kind, name, path)
    if cached is None:
        info = _read_apk(path)
        try:
            _write_cache(kind, name, path, info)
        except OSError:
            pass
        cached = info
        cached.update(_stamp(path))
    package = cached.get("package") or ""
    version = cached.get("version") or ""
    if cached.get("valid") and package:
        detail = f"{package} · {version or '?'}"
    else:
        detail = "package unknown"
    return {
        "detail": detail,
        "size": fmt_size(cached.get("size_bytes") or os.path.getsize(path)),
        "valid": bool(cached.get("valid")),
        "package": package,
        "version": version,
    }


def list_apks():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    items = []
    sources = (
        ("root", PROJECT_ROOT, "Included with the project"),
        ("upload", UPLOAD_DIR, "Uploaded"),
    )
    for kind, folder, where in sources:
        names = sorted(
            name for name in os.listdir(folder)
            if name.lower().endswith(".apk") and os.path.isfile(os.path.join(folder, name))
        )
        for name in names:
            path = os.path.join(folder, name)
            info = describe(kind, name, path)
            items.append({
                "key": f"{kind}:{name}",
                "name": name,
                "where": where,
                "size": info["size"],
                "detail": info["detail"],
                "deletable": kind == "upload",
            })
    return items


def _unique_name(filename):
    base, ext = os.path.splitext(filename)
    candidate = filename
    number = 1
    while os.path.exists(os.path.join(UPLOAD_DIR, candidate)):
        candidate = f"{base}_{number}{ext}"
        number += 1
    return candidate


def save_upload(uploaded, filename):
    """Write an upload only when Androguard can parse its manifest.

    Returns the saved file name. Raises ValueError with a message safe to show.
    The bytes are streamed to a ``.part`` file and renamed after validation.
    """
    header = uploaded.stream.read(4)
    try:
        uploaded.stream.seek(0)
    except OSError:
        pass
    if len(header) < 2 or header[:2] != b"PK":
        raise ValueError("That file is not a ZIP-based APK.")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    dest_name = _unique_name(filename)
    part_path = os.path.join(UPLOAD_DIR, dest_name + ".part")
    final_path = os.path.join(UPLOAD_DIR, dest_name)
    if not _inside(final_path, UPLOAD_DIR):
        raise ValueError("That file name cannot be stored.")

    if os.path.exists(part_path):
        os.remove(part_path)
    try:
        uploaded.save(part_path)
        info = _read_apk(part_path)
        if not info["valid"]:
            raise ValueError("That file has no usable AndroidManifest.xml.")
        os.replace(part_path, final_path)
    except ValueError:
        if os.path.exists(part_path):
            os.remove(part_path)
        raise
    except Exception:
        if os.path.exists(part_path):
            os.remove(part_path)
        raise ValueError("That file could not be read as an APK.")
    try:
        _write_cache("upload", dest_name, final_path, info)
    except OSError:
        pass
    return dest_name


def delete_upload(choice):
    """Delete one uploaded APK. Sample APKs in the project root stay."""
    if not choice or not choice.startswith("upload:"):
        return False, "That file cannot be deleted."
    path = resolve_apk(choice)
    if path is None or not _inside(path, UPLOAD_DIR):
        return False, "That file cannot be deleted."
    name = os.path.basename(path)
    if choice != f"upload:{name}":
        return False, "That file cannot be deleted."
    os.remove(path)
    cache = _cache_path("upload", name)
    if os.path.isfile(cache):
        os.remove(cache)
    return True, f"Deleted {name}."


def cache_file_for(kind, name):
    """Path of the description cache. Tests use this to see that a second view does not rewrite it."""
    return _cache_path(kind, name)
