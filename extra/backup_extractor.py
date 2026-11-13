"""Dynamic: if debuggable / backup allowed, try run-as listing of prefs & databases."""

import re
import subprocess

from analyzers.utils import device_ready

NS = "{http://schemas.android.com/apk/res/android}"


def _shell(args, timeout=20):
    return subprocess.run(
        ["adb", *args], capture_output=True, text=True, timeout=timeout
    )


def run(ctx):
    lines, findings = ["=== Backup / Debuggable Storage Extractor ==="], []
    ok, reason = device_ready()
    if not ok:
        lines.append(f"[!] {reason} — SKIPPED")
        return {
            "tool": "backup_extractor",
            "output": "\n".join(lines),
            "findings": [],
            "skipped": True,
        }

    try:
        package = ctx.apk.get_package()
    except Exception:
        package = None
    if not package:
        lines.append("[!] No package name — SKIPPED")
        return {
            "tool": "backup_extractor",
            "output": "\n".join(lines),
            "findings": [],
            "skipped": True,
        }

    debuggable = False
    allow_backup = True
    root = ctx.get_manifest_root()
    if root is not None:
        app = root.find("application")
        if app is not None:
            debuggable = (app.get(f"{NS}debuggable") or "").lower() == "true"
            allow_backup = (app.get(f"{NS}allowBackup") or "true").lower() == "true"

    lines.append(f"Package: {package}")
    lines.append(f"debuggable={debuggable} allowBackup={allow_backup}")

    if not debuggable and not allow_backup:
        lines.append("[-] Neither debuggable nor backup — no extraction attempted.")
        return {"tool": "backup_extractor", "output": "\n".join(lines), "findings": findings}

    # Prefer run-as when debuggable.
    if debuggable:
        try:
            listing = _shell(["shell", "run-as", package, "ls", "shared_prefs"], timeout=15)
            out = (listing.stdout or "") + (listing.stderr or "")
            lines.append("shared_prefs via run-as:")
            lines.append(out[:1500] or "(empty)")
            if listing.returncode == 0 and out.strip():
                findings.append({
                    "rule_id": "BACKUP_PREFS_LISTED",
                    "evidence": out.strip()[:300],
                })
                for pref in re.findall(r"[\w.\-]+\.xml", out):
                    cat = _shell(
                        ["shell", "run-as", package, "cat", f"shared_prefs/{pref}"],
                        timeout=15,
                    )
                    body = (cat.stdout or "")[:2000]
                    if body and ("password" in body.lower() or "<string" in body):
                        findings.append({
                            "rule_id": "BACKUP_PREFS_SECRET",
                            "evidence": f"{pref}: {body[:400]}",
                        })
                        lines.append(f"  [!] secret-like prefs in {pref}")
            db_ls = _shell(["shell", "run-as", package, "ls", "databases"], timeout=15)
            db_out = (db_ls.stdout or "").strip()
            if db_ls.returncode == 0 and db_out:
                findings.append({
                    "rule_id": "BACKUP_DB_LISTED",
                    "evidence": db_out[:300],
                })
                lines.append(f"databases: {db_out[:300]}")
        except Exception as exc:
            lines.append(f"[!] run-as extraction error: {exc}")

    if allow_backup and not any(f["rule_id"].startswith("BACKUP_") for f in findings):
        findings.append({
            "rule_id": "BACKUP_ALLOWED_HINT",
            "evidence": "allowBackup=true — use adb backup / oandbackupx in lab to extract app data",
        })
        lines.append("[i] Backup allowed — documented extraction hint emitted.")

    if not findings:
        lines.append("[-] No extractable prefs/db content observed.")
    return {"tool": "backup_extractor", "output": "\n".join(lines), "findings": findings}
