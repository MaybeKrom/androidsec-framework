"""Detect SQLite / ContentProvider SQL construction risks in DEX strings."""

import re

from analyzers.dex_scan import const_strings, iter_app_methods, iter_dex_strings, pretty_class

NS = "{http://schemas.android.com/apk/res/android}"


def _exported_provider_names(ctx):
    """Exported providers that declare no readPermission."""
    names = set()
    root = None
    try:
        root = ctx.get_manifest_root()
    except Exception:
        return names
    if root is None:
        return names
    app = root.find("application")
    if app is None:
        return names
    try:
        package = ctx.apk.get_package() or ""
    except Exception:
        package = ""
    for child in app:
        if child.tag != "provider":
            continue
        exported = child.get(f"{NS}exported")
        has_filter = len(child.findall("intent-filter")) > 0
        # Same default as component_analyzer: explicit true, or an intent-filter
        # with the attribute omitted. A missing attribute on a provider is not
        # treated as exported (API 17+ default).
        is_exported = (exported == "true") or (exported is None and has_filter)
        if not is_exported:
            continue
        if child.get(f"{NS}readPermission"):
            continue
        name = child.get(f"{NS}name") or ""
        if name.startswith(".") and package:
            name = package + name
        elif name and "." not in name and package:
            name = package + "." + name
        if name:
            names.add(name)
    return names


PATTERNS = {
    "SQL_RAW_QUERY_CONCAT": re.compile(
        r"(?i)(rawQuery|execSQL)\s*\(.*(\+|String\.format|StringBuilder)"
    ),
    "SQL_SELECTION_CONCAT": re.compile(
        r"(?i)(selection|where).{0,40}(\+|concat)",
    ),
    "SQL_SQLITE_DATABASE": re.compile(r"Landroid/database/sqlite/SQLiteDatabase;"),
    "SQL_QUERY_BUILDER": re.compile(r"SQLiteQueryBuilder|appendWhere"),
}


def run(ctx):
    lines, findings = ["=== SQL Injection Scanner ==="], []
    emitted = set()
    hits = {rule: 0 for rule in PATTERNS}

    for text in iter_dex_strings(ctx):
        for rule, pat in PATTERNS.items():
            if not pat.search(text):
                continue
            hits[rule] += 1
            key = (rule, text[:60])
            if key in emitted:
                continue
            emitted.add(key)
            if rule in ("SQL_RAW_QUERY_CONCAT", "SQL_SELECTION_CONCAT"):
                findings.append({"rule_id": rule, "evidence": text[:160]})
                lines.append(f"  [!] {rule}: {text[:120]}")
            elif rule == "SQL_QUERY_BUILDER" and hits[rule] == 1 and "->" in text:
                # A bare type descriptor (Landroid/.../SQLiteQueryBuilder;) is not
                # proof the app forwards caller SQL. Call sites are handled below.
                findings.append({
                    "rule_id": "SQL_QUERY_BUILDER_USAGE",
                    "evidence": text[:160],
                })
                lines.append(f"  [!] SQL_QUERY_BUILDER_USAGE: {text[:120]}")

    # Lab heuristic: notes / tracker content paths often pair with injectable providers.
    for text in iter_dex_strings(ctx, max_strings=50_000):
        if "content://" in text and any(x in text.lower() for x in ("notes", "tracker", "user")):
            findings.append({
                "rule_id": "SQL_PROVIDER_URI_CANDIDATE",
                "evidence": text[:160],
            })
            lines.append(f"  [!] SQL_PROVIDER_URI_CANDIDATE: {text[:120]}")
            break

    exported = _exported_provider_names(ctx)
    for class_name, method_name, insns in iter_app_methods(ctx):
        if method_name != "query":
            continue
        invokes = "\n".join(output for _op, output in insns if "invoke" in output or "invoke" in _op)
        if "SQLiteQueryBuilder;->query" not in invokes and "SQLiteDatabase;->rawQuery" not in invokes and "SQLiteDatabase;->query" not in invokes:
            continue
        dotted = pretty_class(class_name)
        short = dotted.split(".")[-1]
        is_open = any(short == name or dotted == name or name.endswith("." + short) for name in exported)
        evidence = f"{dotted}->{method_name} forwards the caller selection into SQLite"
        rule = "SQL_PROVIDER_QUERY_PASSTHROUGH"
        findings.append({
            "rule_id": rule,
            "evidence": evidence + (" (exported, no read permission)" if is_open else ""),
            "severity": "High" if is_open else "Medium",
            "confidence": "High" if is_open else "Medium",
        })
        lines.append(f"  [!] {rule}: {evidence}")

    dynamic_sql = re.compile(
        r"(?i)(select\s+.+\s+where\s+.+['\"]$|insert\s+into\s+.+\s+values\s*\(\s*['\"]$)"
    )
    for class_name, method_name, insns in iter_app_methods(ctx):
        invokes = "\n".join(output for op, output in insns if "invoke" in op)
        if "rawQuery" not in invokes and "execSQL" not in invokes:
            continue
        literals = const_strings(insns)
        built = [item for item in literals if dynamic_sql.search(item.strip())]
        if not built:
            continue
        evidence = f"{pretty_class(class_name)}->{method_name}: {built[0][:100]}"
        findings.append({"rule_id": "SQL_RAW_QUERY_CONCAT", "evidence": evidence})
        lines.append(f"  [!] SQL_RAW_QUERY_CONCAT: {evidence}")

    if not findings:
        lines.append("  [-] No SQL concatenation / provider URI candidates detected.")
    else:
        lines.insert(1, f"Findings: {len(findings)}")
    return {"tool": "sql_injection", "output": "\n".join(lines), "findings": findings}
