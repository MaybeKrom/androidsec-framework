"""Detect SQLite / ContentProvider SQL construction risks in DEX strings."""

import re

from analyzers.dex_scan import iter_dex_strings

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
            elif rule == "SQL_QUERY_BUILDER" and hits[rule] == 1:
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

    if not findings:
        lines.append("  [-] No SQL concatenation / provider URI candidates detected.")
    else:
        lines.insert(1, f"Findings: {len(findings)}")
    return {"tool": "sql_injection", "output": "\n".join(lines), "findings": findings}
