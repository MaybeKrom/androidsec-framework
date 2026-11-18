"""Shared DEX string helpers for analyzers."""

from __future__ import annotations


def iter_dex_strings(ctx, max_strings: int = 200_000):
    """Yield unique DEX strings up to max_strings."""
    seen = set()
    count = 0
    for dex in getattr(ctx, "dex", None) or []:
        try:
            strings = dex.get_strings()
        except Exception:
            continue
        if not isinstance(strings, (list, tuple)):
            continue
        for value in strings:
            if not isinstance(value, str) or value in seen:
                continue
            seen.add(value)
            yield value
            count += 1
            if count >= max_strings:
                return


def scan_patterns(ctx, patterns: dict, max_strings: int = 200_000):
    """Return list of {rule_id, evidence} for first match of each (rule, evidence[:80])."""
    findings = []
    emitted = set()
    for text in iter_dex_strings(ctx, max_strings=max_strings):
        for rule, pattern in patterns.items():
            if not pattern.search(text):
                continue
            evidence = text[:120]
            key = (rule, evidence[:80])
            if key in emitted:
                continue
            emitted.add(key)
            findings.append({"rule_id": rule, "evidence": evidence})
    return findings


def zip_text_files(ctx, suffixes=(".xml", ".json", ".properties", ".txt", ".html")):
    """Yield (name, text) for small text-like entries inside the APK zip."""
    try:
        names = ctx.zip.namelist()
    except Exception:
        return
    for name in names:
        lower = name.lower()
        if not any(lower.endswith(suf) for suf in suffixes):
            continue
        try:
            info = ctx.zip.getinfo(name)
            if info.file_size > 512_000:
                continue
            raw = ctx.zip.read(name)
        except Exception:
            continue
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if text.strip():
            yield name, text


_LIBRARY_PREFIXES = (
    "Landroid/",
    "Landroidx/",
    "Landroid/support/",
    "Lcom/google/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lokhttp3/",
    "Lokio/",
    "Lcom/android/volley/",
    "Lcom/android/org/",
    "Ljavax/",
    "Ljava/",
    "Ldalvik/",
    "Lorg/bouncycastle/",
    "Lcom/squareup/",
    "Lcom/facebook/",
)


def pretty_class(raw: str) -> str:
    name = raw[1:] if raw.startswith("L") else raw
    if name.endswith(";"):
        name = name[:-1]
    return name.replace("/", ".")


def app_class_prefix(ctx) -> str:
    try:
        package = ctx.apk.get_package() or ""
    except Exception:
        package = ""
    if not package:
        return ""
    return "L" + package.replace(".", "/") + "/"


def const_strings(insns) -> list:
    """Pull const-string literals out of androguard instruction output."""
    found = []
    for op, output in insns:
        if not str(op).startswith("const-string"):
            continue
        quote = output.find('"')
        if quote < 0:
            continue
        literal = output[quote + 1 :]
        if literal.endswith('"'):
            literal = literal[:-1]
        found.append(literal)
    return found


def iter_app_methods(ctx):
    """Yield (class_name, method_name, [(op, output), ...]) for the app package.

    Library bytecode (Play Services, support-v4, OkHttp) shares the DEX string
    pool and was producing false positives such as addJavascriptInterface.
    Results are cached on the context so several analyzers can reuse one walk.
    """
    cached = getattr(ctx, "_app_methods_cache", None)
    if cached is not None:
        return cached

    dx = getattr(ctx, "dx", None)
    prefix = app_class_prefix(ctx)
    methods = []
    if dx is None or not prefix:
        ctx._app_methods_cache = methods
        return methods

    for analysis in dx.get_methods():
        try:
            if analysis.is_external():
                continue
        except Exception:
            continue
        method = analysis.get_method()
        class_name = method.get_class_name()
        if not class_name.startswith(prefix):
            continue
        if class_name.startswith(_LIBRARY_PREFIXES):
            continue
        try:
            insns = [
                (ins.get_name(), ins.get_output() or "")
                for ins in method.get_instructions()
            ]
        except Exception:
            continue
        methods.append((class_name, method.get_name(), insns))

    ctx._app_methods_cache = methods
    return methods
