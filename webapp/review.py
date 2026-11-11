"""Explain one finding with a key the user types in for that request.

The key is sent to the provider they pick and is not written to disk. The
saved row is the written review, not an exploit script. This module does not
call adb.
"""

import ipaddress
import json
import os
import re
import socket
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from flask import Blueprint, abort, render_template, request

from reporter.report_generator import sorted_findings
from webapp.jobs import is_live_report

bp = Blueprint("review", __name__)

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(WEB_DIR)
REPORT_DIR = os.path.join(PROJECT_ROOT, "output_reports")
DB_PATH = os.path.join(WEB_DIR, "reviews.sqlite")

_REPORT_NAME = re.compile(r"security_report_\d{8}_\d{6}\.html$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")
READY_LINE = "Hi, im fully ready"
PING_PROMPT = "Reply with exactly this sentence and nothing else: Hi, im fully ready"
_PING_TIMEOUT = 30
_REVIEW_TIMEOUT = 60
_MAX_BODY = 1_000_000
_FIELD_LIMIT = 4000
_ANTHROPIC_VERSION = "2023-06-01"

# Defaults are starting points. The form sends whatever model name the user leaves in the box.
_PROVIDER_ROWS = (
    ("openai", "OpenAI", "chat", "https://api.openai.com/v1/chat/completions", "gpt-5.2"),
    ("anthropic", "Anthropic (Claude)", "anthropic", "https://api.anthropic.com/v1/messages", "claude-sonnet-4-5"),
    ("gemini", "Google Gemini", "gemini", "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent", "gemini-3.5-flash"),
    ("openrouter", "OpenRouter", "chat", "https://openrouter.ai/api/v1/chat/completions", "openai/gpt-5.2"),
    ("deepseek", "DeepSeek", "chat", "https://api.deepseek.com/chat/completions", "deepseek-chat"),
    ("xai", "xAI", "chat", "https://api.x.ai/v1/chat/completions", "grok-4.7"),
    ("custom", "Other (OpenAI-compatible)", "custom", "", ""),
)
PROVIDERS = {
    row[0]: {"label": row[1], "kind": row[2], "url": row[3], "model": row[4]}
    for row in _PROVIDER_ROWS
}

RESPONSIBILITY_TEXT = (
    "We are not responsible for any misuse of the AI, for token usage, or if the review fails."
)
KEY_TEXT = "I confirm that my API key is not stored."


class ReviewError(Exception):
    pass


def provider_choices():
    return [
        {"id": row[0], "label": row[1], "model": row[4], "custom": row[0] == "custom"}
        for row in _PROVIDER_ROWS
    ]


def load_finding(report_dir, report_name, index):
    """Return metadata, summary, and one finding from a report JSON file."""
    if not report_name or not _REPORT_NAME.fullmatch(report_name) or index < 0:
        raise LookupError("report")
    json_name = report_name[:-5] + ".json"
    path = os.path.join(report_dir, json_name)
    root = os.path.realpath(report_dir)
    real = os.path.realpath(path)
    if real != os.path.join(root, json_name) or not os.path.isfile(real):
        raise LookupError("report")
    try:
        with open(real, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise LookupError("report") from exc
    findings = sorted_findings(data.get("findings") or [])
    if index >= len(findings) or not isinstance(findings[index], dict):
        raise LookupError("finding")
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {"metadata": metadata, "summary": summary, "finding": findings[index], "index": index}


def review_prompt(loaded):
    """Educational context plus one finding. This does not ask for an exploit."""
    metadata = loaded["metadata"]
    summary = loaded["summary"]
    finding = loaded["finding"]

    def clip(value):
        text = str(value or "").replace("\x00", "")
        if len(text) > _FIELD_LIMIT:
            return text[:_FIELD_LIMIT] + "…"
        return text

    return (
        "You are helping students at King Saud University understand one finding "
        "from their own authorized security assessment. This is a graduation project. "
        "The user confirmed they are allowed to assess this application.\n\n"
        "Explain the finding in plain language. Use the evidence quoted below. "
        "Say why it matters and how to fix it. Do not write exploit code, payloads, "
        "or steps to attack the application.\n\n"
        f"Package: {clip(metadata.get('package'))}\n"
        f"App name: {clip(metadata.get('app_name'))}\n"
        f"Version: {clip(metadata.get('version_name'))}\n"
        f"Risk: {clip(summary.get('level'))} ({clip(summary.get('score'))}/100)\n"
        f"Severity: {clip(finding.get('severity'))}\n"
        f"Rule: {clip(finding.get('rule_id'))}\n"
        f"Title: {clip(finding.get('title'))}\n"
        f"Evidence: {clip(finding.get('evidence'))}\n"
        f"Recommendation already in the report: {clip(finding.get('recommendation'))}\n"
        f"MASVS: {clip(finding.get('masvs'))}\n"
    )


def _joined(blocks):
    parts = []
    if isinstance(blocks, str):
        parts.append(blocks)
    elif isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                if block.get("type") in (None, "text", "output_text"):
                    parts.append(block["text"])
    return "\n".join(part for part in parts if part).strip()


def response_text(payload):
    """Read a reply from chat completions, Anthropic, Gemini, or the xAI responses shape."""
    if not isinstance(payload, dict):
        return ""
    if isinstance(payload.get("output_text"), str) and payload["output_text"].strip():
        return payload["output_text"].strip()
    choices = payload.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            text = _joined(message.get("content"))
            if text:
                return text
    if isinstance(payload.get("content"), list):
        text = _joined(payload.get("content"))
        if text:
            return text
    output = payload.get("output")
    if isinstance(output, list):
        parts = []
        for item in output:
            if isinstance(item, dict):
                parts.append(_joined(item.get("content")))
        text = "\n".join(part for part in parts if part).strip()
        if text:
            return text
    candidates = payload.get("candidates")
    if isinstance(candidates, list) and candidates and isinstance(candidates[0], dict):
        content = candidates[0].get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        if isinstance(parts, list):
            text = "\n".join(
                part["text"] for part in parts
                if isinstance(part, dict) and isinstance(part.get("text"), str) and part["text"]
            ).strip()
            if text:
                return text
    return ""


def _clean_model(provider, model):
    spec = PROVIDERS.get(provider)
    if spec is None:
        raise ReviewError("Choose a provider.")
    text = (model or "").strip() or spec["model"]
    if not text:
        raise ReviewError("Enter a model name.")
    if not _MODEL_RE.fullmatch(text):
        raise ReviewError("Enter a model name using letters, numbers, and . _ : / -")
    if spec["kind"] == "gemini" and "/" in text:
        raise ReviewError("A Gemini model name cannot include a slash.")
    return text


def _host_kind(hostname):
    name = hostname.lower().rstrip(".")
    if name == "localhost":
        return "local"
    if name == "metadata.google.internal":
        raise ReviewError("That API address is not allowed.")
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return "name"
    if ip.is_loopback:
        return "local"
    if not ip.is_global:
        raise ReviewError("That API address is not allowed.")
    return "public"


def _chat_url(base):
    """OpenAI-compatible chat URL. Remote hosts must be https. Loopback may be http."""
    raw = (base or "").strip()
    if not raw or len(raw) > 500 or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ReviewError("Enter an https API address.")
    parts = urllib.parse.urlsplit(raw)
    if parts.username or parts.password:
        raise ReviewError("The API address cannot include a username or password.")
    if parts.query or parts.fragment:
        raise ReviewError("The API address cannot include a query or a fragment.")
    if not parts.hostname:
        raise ReviewError("Enter an https API address.")
    kind = _host_kind(parts.hostname)
    if parts.scheme == "https":
        pass
    elif parts.scheme == "http" and kind == "local":
        pass
    elif parts.scheme == "http":
        raise ReviewError("A remote API address must use https://.")
    else:
        raise ReviewError("The API address must start with https://.")
    path = (parts.path or "").rstrip("/")
    if not path.endswith("/chat/completions"):
        path = path + "/chat/completions"
    return f"{parts.scheme}://{parts.netloc}{path}"


def _clean_key(api_key):
    key = (api_key or "").strip()
    if not key or any(ch.isspace() or ord(ch) < 32 for ch in key):
        raise ReviewError("Enter an API key.")
    return key


def build_provider_request(provider, model, base_url, api_key, prompt):
    """Return url, headers, and body. The key is a header, never part of the URL."""
    spec = PROVIDERS.get(provider)
    if spec is None:
        raise ReviewError("Choose a provider.")
    key = _clean_key(api_key)
    chosen = _clean_model(provider, model)
    kind = spec["kind"]
    if kind == "chat":
        url = spec["url"]
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        body = {"model": chosen, "messages": [{"role": "user", "content": prompt}]}
    elif kind == "custom":
        url = _chat_url(base_url)
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        body = {"model": chosen, "messages": [{"role": "user", "content": prompt}]}
    elif kind == "anthropic":
        url = spec["url"]
        headers = {
            "x-api-key": key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }
        body = {
            "model": chosen,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
    elif kind == "gemini":
        quoted = urllib.parse.quote(chosen, safe="")
        url = spec["url"].format(model=quoted)
        headers = {"x-goog-api-key": key, "Content-Type": "application/json"}
        body = {"contents": [{"parts": [{"text": prompt}]}]}
    else:
        raise ReviewError("Choose a provider.")
    if key in url:
        raise ReviewError("The API address cannot contain the API key.")
    return url, headers, json.dumps(body).encode("utf-8")


def ask_model(api_key, prompt, timeout, provider="openai", model="", base_url=""):
    """POST one prompt. The key is only a request header for this call."""
    url, headers, body = build_provider_request(provider, model, base_url, api_key, prompt)
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(_MAX_BODY)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ReviewError("The API key was rejected.") from None
        if exc.code == 429:
            raise ReviewError("The AI service is rate limiting requests.") from None
        raise ReviewError(f"The AI service returned status {exc.code}.") from None
    except (TimeoutError, socket.timeout) as exc:
        raise ReviewError("The AI service took too long.") from exc
    except urllib.error.URLError as exc:
        if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
            raise ReviewError("The AI service took too long.") from exc
        raise ReviewError("The AI service could not be reached.") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ReviewError("The AI service returned a response that was not JSON.") from exc
    text = response_text(payload)
    if not text:
        raise ReviewError("The AI service returned an empty reply.")
    return text


def _connect(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            review_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    return conn


def latest_review(package, rule_id, db_path=None):
    if not package or not rule_id:
        return None
    conn = _connect(db_path or DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT title, severity, review_text, created_at
            FROM reviews
            WHERE package = ? AND rule_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (package, rule_id),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {
        "title": row[0],
        "severity": row[1],
        "review_text": row[2],
        "created_at": row[3],
    }


def save_review(package, rule_id, title, severity, review_text, db_path=None):
    text = (review_text or "").strip()
    if not package or not rule_id or not text:
        raise ReviewError("The review could not be saved.")
    if len(text) > 20000:
        text = text[:20000] + "…"
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    conn = _connect(db_path or DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO reviews (package, rule_id, title, severity, review_text, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (package, rule_id, title or "", severity or "", text, created),
        )
        conn.commit()
    finally:
        conn.close()
    return {"title": title or "", "severity": severity or "", "review_text": text, "created_at": created}


def _page_context(loaded, saved, error=None, ready_line=None, fresh=None, provider="openai", model="", base_url=""):
    finding = loaded["finding"]
    metadata = loaded["metadata"]
    spec = PROVIDERS.get(provider) or PROVIDERS["openai"]
    shown = provider if provider in PROVIDERS else "openai"
    return {
        "report": request.values.get("report", ""),
        "index": loaded["index"],
        "package": metadata.get("package") or "",
        "app_name": metadata.get("app_name") or "",
        "version": metadata.get("version_name") or "",
        "finding": finding,
        "saved": saved,
        "error": error,
        "ready_line": ready_line,
        "fresh": fresh,
        "responsibility_text": RESPONSIBILITY_TEXT,
        "key_text": KEY_TEXT,
        "providers": provider_choices(),
        "provider": shown,
        "model": model if model != "" else spec["model"],
        "base_url": base_url or "",
    }


@bp.route("/review", methods=["GET", "POST"])
def page():
    report_name = request.values.get("report", "")
    try:
        index = int(request.values.get("i", ""))
    except (TypeError, ValueError):
        abort(404)
    if not is_live_report(report_name):
        abort(404)
    try:
        loaded = load_finding(REPORT_DIR, report_name, index)
    except LookupError:
        abort(404)

    finding = loaded["finding"]
    package = str(loaded["metadata"].get("package") or "unknown")
    rule_id = str(finding.get("rule_id") or "unknown")
    saved = latest_review(package, rule_id)
    error = None
    ready_line = None
    fresh = None
    provider = "openai"
    model = ""
    base_url = ""

    if request.method == "POST":
        provider = (request.form.get("provider") or "").strip()
        model = request.form.get("model") or ""
        base_url = request.form.get("base_url") or ""
        acknowledged = (
            request.form.get("responsibility") == "yes"
            and request.form.get("key_not_stored") == "yes"
        )
        api_key = request.form.get("api_key") or ""
        if not acknowledged:
            error = "Check both acknowledgment boxes before sending a review."
        elif provider not in PROVIDERS:
            error = "Choose a provider."
        elif not api_key.strip():
            error = "Enter an API key."
        else:
            try:
                ready_line = ask_model(
                    api_key, PING_PROMPT, _PING_TIMEOUT,
                    provider=provider, model=model, base_url=base_url,
                )
                if READY_LINE not in ready_line:
                    error = "The model did not confirm it was ready, so the finding was not sent."
                    ready_line = None
                else:
                    fresh_text = ask_model(
                        api_key, review_prompt(loaded), _REVIEW_TIMEOUT,
                        provider=provider, model=model, base_url=base_url,
                    )
                    fresh = save_review(
                        package,
                        rule_id,
                        str(finding.get("title") or ""),
                        str(finding.get("severity") or ""),
                        fresh_text,
                    )
                    saved = fresh
            except ReviewError as exc:
                error = str(exc)
                ready_line = None
                fresh = None
        api_key = ""

    return render_template(
        "review.html",
        **_page_context(loaded, saved, error, ready_line, fresh, provider, model, base_url),
    )
