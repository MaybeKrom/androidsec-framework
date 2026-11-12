import argparse
import importlib
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

from analyzers.utils import sha256_file, fmt_size
from context import AppContext
from engine.risk_engine import RiskEngine
from reporter.report_generator import ReportGenerator
from rules.owasp_mapper import OWASPMapper
from rules.rules_engine import RulesEngine

ANALYZERS = [
    ("apk_info",        "analyzers.apk_info_analyzer",        "APK metadata and signing certificates"),
    ("manifest",        "analyzers.manifest_analyzer",        "Manifest flags: debuggable, backup, cleartext"),
    ("permission",      "analyzers.permission_analyzer",      "Permission sensitivity (location, SMS, camera)"),
    ("component",       "analyzers.component_analyzer",       "Exported activities, services, receivers, providers"),
    ("attack_surface",  "analyzers.attack_surface_analyzer",  "Deep links and browsable intent-filters"),
    ("secret_detector", "analyzers.secret_detector",          "Secrets and credentials in DEX and native libs"),
    ("static_code",     "analyzers.static_code_scanner",      "Weak crypto, insecure random, trust-all certs"),
    ("storage",         "analyzers.storage_analyzer",         "World-readable files and sensitive storage use"),
    ("network",         "analyzers.network_config_analyzer",  "Cleartext traffic and network security config"),
    ("webview",         "extra.webview_analyzer",             "WebView JavaScript bridge and file-access settings"),
    ("api_extractor",   "extra.api_extractor",                "URLs and cloud endpoints from DEX strings"),
    ("deeplink_fuzzer", "extra.deeplink_fuzzer",              "Browsable activity enumeration"),
    ("cloud_checker",   "extra.cloud_misconfig_checker",      "Firebase read-access checks"),
    ("adb_inspector",   "analyzers.adb_device_inspector",     "Device properties and install status (needs ADB)"),
    ("runtime",         "analyzers.runtime_inspector",        "Launch and crash monitoring (needs ADB)"),
    ("frida",           "analyzers.frida_runtime_analyzer",   "Runtime hooks for prefs and crypto (needs Frida)"),
    ("log",             "analyzers.log_analyzer",             "Logcat scan for leaked secrets (needs ADB)"),
]

DYNAMIC_ANALYZERS = {"adb_inspector", "runtime", "frida", "log"}
BASE = os.path.dirname(os.path.abspath(__file__))


def _safe_meta(apk_obj, method_name, default="Unknown"):
    try:
        val = getattr(apk_obj, method_name)()
        if val is None or str(val).strip() == "": return default
        return str(val)
    except Exception:
        return default


def _notify(on_progress, tool_id, message):
    if not on_progress:
        return
    try:
        on_progress(tool_id, message)
    except Exception:
        pass


def run_scan(apk_path, output_dir=None, only=None, skip=None,
             static_only=False, start_adb=True, on_progress=None):
    """Run analyzers and write the HTML and JSON reports.

    only: analyzer ids to run. None or an empty collection runs every analyzer
    that is not skipped. skip: analyzer ids to skip. static_only also skips
    the dynamic analyzers. start_adb tries `adb start-server` first (CLI default).
    on_progress(tool_id, message) is optional and is not used by the CLI.
    """
    apk = apk_path
    if not os.path.exists(apk):
        raise FileNotFoundError(apk)

    skip_set = set(skip or [])
    if static_only:
        skip_set.update(DYNAMIC_ANALYZERS)
    only_set = set(only or [])

    out_dir = output_dir or os.path.join(BASE, "output_reports")
    os.makedirs(out_dir, exist_ok=True)

    if start_adb and not static_only and shutil.which("adb"):
        try: subprocess.run(["adb", "start-server"], capture_output=True, timeout=10)
        except Exception: pass

    print("=" * 60)
    print(f"[*] androidsec scanning: {apk}")
    print("=" * 60)

    ctx = AppContext(apk)
    tool_results = []

    for tool_id, mod_path, _desc in ANALYZERS:
        if tool_id in skip_set or (only_set and tool_id not in only_set):
            continue

        print(f"[*] Running {tool_id}...", end=" ", flush=True)
        _notify(on_progress, tool_id, f"Running {tool_id}…")
        t0 = time.time()
        try:
            mod = importlib.import_module(mod_path)
            result = mod.run(ctx)
            dt = time.time() - t0
            tool_results.append(result)
            flag = "SKIPPED" if result.get("skipped") else f"{len(result['findings'])} findings"
            print(f"done ({dt:.1f}s, {flag})")
        except Exception as e:
            print(f"FAILED ({type(e).__name__}: {e})")
            tool_results.append({"tool": tool_id, "output": f"[ERROR] {e}", "findings": [], "skipped": True})
        _notify(on_progress, tool_id, f"Done {tool_id}")

    raw = []
    for r in tool_results:
        raw.extend(r["findings"])

    _notify(on_progress, "", "Writing the report…")
    findings = RulesEngine(os.path.join(BASE, "rules", "rules.json")).enrich(raw)
    findings = OWASPMapper(os.path.join(BASE, "rules", "owasp_mapping.json")).apply(findings)
    summary = RiskEngine().compute(findings)

    apk_obj = ctx.apk
    pkg_name = _safe_meta(apk_obj, "get_package")
    app_name = _safe_meta(apk_obj, "get_app_name", pkg_name)

    target_sdk = "Unknown"
    min_sdk = "Unknown"

    root = ctx.get_manifest_root()
    if root is not None:
        sdk_node = root.find("uses-sdk")
        if sdk_node is not None:
            ns = "{http://schemas.android.com/apk/res/android}"
            target_sdk = sdk_node.get(f"{ns}targetSdkVersion", "Unknown")
            min_sdk = sdk_node.get(f"{ns}minSdkVersion", "Unknown")

    if target_sdk == "Unknown":
        target_sdk = _safe_meta(apk_obj, "get_target_sdk_version")
    if min_sdk == "Unknown":
        min_sdk = _safe_meta(apk_obj, "get_min_sdk_version")

    metadata = {
        "target":          apk,
        "target_basename": os.path.basename(apk),
        "timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sha256":          ctx.sha256,
        "size_human":      fmt_size(os.path.getsize(apk)),
        "package":         pkg_name,
        "app_name":        app_name,
        "version_name":    _safe_meta(apk_obj, "get_androidversion_name"),
        "min_sdk":         min_sdk,
        "target_sdk":      target_sdk,
    }

    reporter = ReportGenerator(metadata, tool_results, findings, summary)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(out_dir, f"security_report_{stamp}.html")
    json_path = os.path.join(out_dir, f"security_report_{stamp}.json")
    reporter.save_html(html_path)
    reporter.save_json(json_path)

    print("=" * 60)
    print(f"[+] Risk Level : {summary['level']} ({summary['score']}/100)")
    print(f"[+] Findings   : {summary['counts']}")
    print(f"[+] HTML       : {html_path}")
    print(f"[+] JSON       : {json_path}")

    return {
        "html_path": html_path,
        "json_path": json_path,
        "summary": summary,
        "metadata": metadata,
    }


def main():
    parser = argparse.ArgumentParser(
        prog="androidsec",
        description="androidsec — Automated Android APK Security Assessment Tool (Static & Dynamic)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("apk", nargs="?", default=None, help="Path to the Android APK file to analyze.")
    parser.add_argument("--skip", nargs="+", default=[], metavar="ANALYZER", help="Analyzer names to skip (e.g. --skip frida runtime).")
    parser.add_argument("--only", nargs="+", default=[], metavar="ANALYZER", help="Run only specified analyzers (e.g. --only manifest component).")
    parser.add_argument("--static-only", action="store_true", help="Run only static analysis modules (skip ADB/Frida/logcat).")
    parser.add_argument("--no-gui", action="store_true", help="Skip the analyzer picker and run from the command line.")
    parser.add_argument("--no-adb", action="store_true", help="Do not attempt to start or connect to ADB server.")
    parser.add_argument("-o", "--output", default=os.path.join(BASE, "output_reports"), help="Output directory for reports (default: output_reports/).")
    parser.add_argument("--list-analyzers", action="store_true", help="List all registered analyzers and exit.")
    parser.add_argument("-v", "--version", action="version", version="androidsec 1.0.0")

    args = parser.parse_args()

    if args.list_analyzers:
        print("Registered Analyzers:")
        print("  Static Analyzers:")
        for name, mod, _desc in ANALYZERS:
            if name not in DYNAMIC_ANALYZERS:
                print(f"    - {name:<18} ({mod})")
        print("\n  Dynamic Analyzers (require ADB device):")
        for name, mod, _desc in ANALYZERS:
            if name in DYNAMIC_ANALYZERS:
                print(f"    - {name:<18} ({mod})")
        return

    if not args.apk:
        parser.print_help()
        sys.exit(1)

    apk = args.apk
    if not os.path.exists(apk):
        sys.exit(f"[!] File not found: {apk}")

    skip = set(args.skip or [])
    if args.static_only:
        skip.update(DYNAMIC_ANALYZERS)
    only = set(args.only or [])

    cli_selected = bool(args.only or args.skip or args.static_only or args.no_gui)
    if not cli_selected:
        from gui import pick_analyzers
        entries = [
            {
                "id": tool_id,
                "filename": mod_path.rsplit(".", 1)[-1] + ".py",
                "description": desc,
            }
            for tool_id, mod_path, desc in ANALYZERS
        ]
        try:
            selected = pick_analyzers(entries, apk)
        except RuntimeError as exc:
            sys.exit(
                f"[!] Could not open the analyzer picker: {exc}\n"
                "    Use --no-gui to run without a window."
            )
        if not selected:
            print("[*] Cancelled. No analyzers were run.")
            return
        only = set(selected)

    run_scan(
        apk,
        output_dir=args.output,
        only=only,
        skip=skip,
        static_only=args.static_only,
        start_adb=not args.no_adb,
    )


if __name__ == "__main__":
    main()
