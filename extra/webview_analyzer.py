"""WebView checks on app-package call sites, not the shared DEX string pool.

Bare method names such as addJavascriptInterface appear because Play Services
(or the app) references them. A Critical JS-bridge finding is emitted only when
the application package itself invokes WebView.addJavascriptInterface.
"""

from analyzers.dex_scan import const_strings, iter_app_methods, pretty_class


def run(ctx):
    lines, findings = ["=== WebView Security Analysis ==="], []
    emitted = set()

    def _emit(rule, evidence):
        key = (rule, evidence[:80])
        if key in emitted:
            return
        emitted.add(key)
        findings.append({"rule_id": rule, "evidence": evidence})
        lines.append(f"  [!] {rule}: {evidence[:140]}")

    app_methods = list(iter_app_methods(ctx))
    lines.append(f"App methods inspected: {len(app_methods)}")
    by_class = {}
    for class_name, method_name, insns in app_methods:
        by_class.setdefault(class_name, []).append((method_name, insns))

    for class_name, method_name, insns in app_methods:
        invokes = "\n".join(output for op, output in insns if "invoke" in op)
        literals = const_strings(insns)
        where = f"{pretty_class(class_name)}->{method_name}"

        if "->addJavascriptInterface(" in invokes:
            _emit("WEBVIEW_JS_BRIDGE", where)

        javascript = "setJavaScriptEnabled" in invokes
        file_url = any(
            literal.startswith("file://") or "Statements_" in literal
            for literal in literals
        )
        external = "getExternalStorageDirectory" in invokes or "getExternalStoragePublicDirectory" in invokes
        if javascript and (file_url or external):
            _emit(
                "WEBVIEW_UNTRUSTED_FILE",
                f"{where} loads file/external content with JavaScript enabled",
            )
        elif javascript:
            _emit("WEBVIEW_JS_ENABLED", where)

        if "setAllowUniversalAccessFromFileURLs" in invokes:
            _emit("WEBVIEW_UNIVERSAL_ACCESS", where)
        if "setAllowFileAccessFromFileURLs" in invokes:
            _emit("WEBVIEW_FILE_ACCESS", where)

    for class_name, methods in by_class.items():
        blob = "\n".join(
            output
            for _, insns in methods
            for op, output in insns
            if "invoke" in op
        )
        controlled = "getText(" in blob or "getStringExtra" in blob or "getData(" in blob
        if "setJavaScriptEnabled" in blob and "WebView;->loadUrl" in blob and controlled:
            _emit(
                "WEBVIEW_USER_URL",
                f"{pretty_class(class_name)} enables JavaScript and loads a URL from an intent or text field",
            )

    if not findings:
        lines.append("  [-] No app-package WebView risks detected.")
    return {"tool": "webview", "output": "\n".join(lines), "findings": findings}
