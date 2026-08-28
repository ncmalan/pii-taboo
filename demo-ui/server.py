"""Standalone local server for the side-by-side PII demo."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlencode, urlparse


DEMO_DIR = Path(__file__).resolve().parent
PROJECT_DIR = DEMO_DIR.parent
sys.path.insert(0, str(PROJECT_DIR))

from demo import call_llm  # noqa: E402
from pii_guard import (  # noqa: E402
    PiiVault,
    PrivacyFilterClient,
    identity_name_context,
    model_messages,
    protect_messages,
)


PRIVACY_URL = os.getenv("PII_PRIVACY_URL", "http://127.0.0.1:8081")
LLM_URL = os.getenv("PII_LLM_URL", "http://127.0.0.1:8080/v1/chat/completions")
LLM_MODEL = os.getenv("PII_LLM_MODEL", "local-model")
LLM_API_KEY = os.getenv("PII_LLM_API_KEY", "")
LLM_REASONING_EFFORT = os.getenv("PII_LLM_REASONING_EFFORT", "low")
VAULT_DB = os.getenv("PII_DEMO_VAULT_DB", str(PROJECT_DIR / ".private/state/demo-vault.sqlite3"))
VAULT_KEY = os.getenv("PII_VAULT_KEY")
PROJECT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
TOOL_CALL = "lookup_project_contact(record_id='synthetic-contact-17')"
TOOL_RESULT = json.dumps(
    {
        "synthetic": True,
        "record_id": "synthetic-contact-17",
        "name": "John Blake",
        "email": "john.blake@example.com",
        "phone": "+27 82 555 0199",
        "last_updated": {
            "value": "2026-08-14",
            "kind": "record_metadata",
            "not_evidence_of": ["authority revocation", "authority reassignment"],
        },
        "evidence": {
            "provenance": "synthetic project contact directory",
            "authoritative_for": ["contact fields returned for this record"],
            "not_authoritative_for": [
                "identity equivalence across person mentions",
                "authority or authority-change events",
            ],
        },
    },
    indent=2,
)
WEB_SEARCH_ENDPOINT = "https://en.wikipedia.org/w/api.php"
WEB_SEARCH_INTENT = re.compile(r"\b(?:web search|search the web|look (?:it )?up online)\b", re.I)
EMAIL_DOMAIN_HANDLE = re.compile(r"\bEMAIL-SH-[A-Z2-7]{12}-DOMAIN\b")


conversations: dict[tuple[str, str], dict] = {}
detector = PrivacyFilterClient(PRIVACY_URL).detect


def service_health(url: str, healthy_detail: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            payload = json.load(response)
        ok = payload.get("status") == "ok"
        return {"ok": ok, "detail": healthy_detail if ok else "loading"}
    except (OSError, ValueError, urllib.error.URLError):
        return {"ok": False, "detail": "unavailable"}


def protected_message(message: dict, vault: PiiVault) -> dict:
    protected, _ = protect_messages([message], detector, vault)
    return protected[-1]


def wikipedia_request(parameters: dict) -> dict:
    request = urllib.request.Request(
        f"{WEB_SEARCH_ENDPOINT}?{urlencode(parameters)}",
        headers={"User-Agent": "PII-Taboo-POC/1.0"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def web_search_company(domain: str) -> dict:
    search = wikipedia_request(
        {
            "action": "query",
            "list": "search",
            "srsearch": f'"{domain}" company',
            "srnamespace": 0,
            "srlimit": 1,
            "format": "json",
            "formatversion": 2,
        }
    )
    matches = search.get("query", {}).get("search", [])
    if not matches:
        return {"query": domain, "status": "no public company profile found"}
    title = matches[0]["title"]
    profile = wikipedia_request(
        {
            "action": "query",
            "prop": "extracts|info",
            "titles": title,
            "exintro": 1,
            "explaintext": 1,
            "inprop": "url",
            "format": "json",
            "formatversion": 2,
        }
    )["query"]["pages"][0]
    return {
        "query": domain,
        "company": title,
        "summary": profile.get("extract", "")[:1_500],
        "source": profile.get("canonicalurl"),
    }


def protect_web_result(result: dict, domain_handle: str, vault: PiiVault) -> dict:
    raw = json.dumps(result, indent=2, ensure_ascii=False)
    protected = raw.replace(result["query"], domain_handle)
    return protected_message({"role": "tool", "content": protected}, vault)


def request_context(payload: dict, require_message: bool = False):
    session_id = payload.get("session_id")
    project_id = payload.get("project_id", "demo-project")
    if not isinstance(session_id, str) or not 1 <= len(session_id) <= 128:
        raise ValueError("invalid session_id")
    if not isinstance(project_id, str) or not PROJECT_PATTERN.fullmatch(project_id):
        raise ValueError("project_id must use 1–64 letters, numbers, dashes, or underscores")
    vault = PiiVault(VAULT_DB, project_id, VAULT_KEY)
    state = conversations.setdefault(
        (session_id, project_id),
        {"protected_history": [], "turns": [], "pending": None},
    )
    if require_message:
        message = payload.get("message")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("message must not be empty")
    return vault, state


def model_config(payload: dict) -> tuple[str, str, str]:
    config = payload.get("model_config") or {}
    if not isinstance(config, dict):
        raise ValueError("model_config must be an object")
    url = config.get("url") or LLM_URL
    model = config.get("model") or LLM_MODEL
    requested_api_key = config.get("api_key") or ""
    if not all(isinstance(value, str) for value in (url, model, requested_api_key)):
        raise ValueError("model URL, name, and API key must be strings")
    url, model = url.strip(), model.strip()
    api_key = requested_api_key or (LLM_API_KEY if url == LLM_URL else "")
    parsed = urlparse(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or len(url) > 2_048
    ):
        raise ValueError("model URL must be an HTTP(S) endpoint without embedded credentials")
    if not model or len(model) > 256 or len(api_key) > 8_192:
        raise ValueError("invalid model name or API key length")
    return url, model, api_key


def handle_count(history: list[dict]) -> int:
    return len(
        set(
            re.findall(
                r"\b(?:ACCOUNT|ADDRESS|EMAIL|NAME|PERSON|PHONE|URL|DATE|SECRET)-SH-[A-Z2-7]{12}(?:-(?:MONTH-NAME-ENG|MONTH-ISO|DAY-NUM|DAY-ISO|UNRESOLVED|FN|LN|USER|DOMAIN|DAY|MONTH|YEAR))?\b",
                "\n".join(item["content"] for item in history),
            )
        )
    )


def trusted_person_links(context: dict, vault: PiiVault) -> list[dict]:
    """Restore candidate labels only for the trusted demo UI response."""
    return [
        {
            **link,
            "candidate_value": vault.restore(link["candidate"]),
            "canonical_value": vault.restore(link["canonical"]),
        }
        for link in context["person_links"]
    ]


def protect_user(payload: dict) -> dict:
    vault, state = request_context(payload, require_message=True)
    if state["pending"]:
        raise ValueError("finish the pending response before sending another message")
    message = payload["message"].strip()
    filter_started = time.monotonic()
    protected_user = protected_message({"role": "user", "content": message}, vault)
    filter_ms = round((time.monotonic() - filter_started) * 1000)
    turn = {
        "role": "user",
        "kind": "message",
        "display": message,
        "protected": protected_user["content"],
    }
    state["protected_history"].append(protected_user)
    state["turns"].append(turn)
    state["pending"] = {
        "message": message,
        "include_tool": bool(payload.get("include_tool")),
        "filter_ms": filter_ms,
    }
    identity_status = identity_name_context(state["protected_history"], vault)
    return {
        "turn": turn,
        "identity_status": identity_status,
        "person_links": trusted_person_links(identity_status, vault),
        "metrics": {
            "filter_ms": filter_ms,
            "handles": handle_count(state["protected_history"]),
        },
    }


def complete_chat(payload: dict) -> dict:
    vault, state = request_context(payload)
    pending = state["pending"]
    if not pending:
        raise ValueError("no protected user message is waiting for completion")
    message = pending["message"]
    include_tool = pending["include_tool"]
    history = list(state["protected_history"])
    new_turns = []
    filter_ms = pending["filter_ms"]
    protected_user = history[-1]

    domain_match = EMAIL_DOMAIN_HANDLE.search(protected_user["content"])
    if domain_match and WEB_SEARCH_INTENT.search(message):
        domain_handle = domain_match.group()
        protected_call = f"web_search(query='{domain_handle}')"
        display_call = vault.restore(protected_call)
        history.append({"role": "assistant", "content": f"Tool call: {protected_call}"})
        new_turns.append(
            {
                "role": "agent",
                "kind": "tool_call",
                "display": display_call,
                "protected": protected_call,
            }
        )
        result = web_search_company(vault.restore(domain_handle))
        raw_result = json.dumps(result, indent=2, ensure_ascii=False)
        filter_started = time.monotonic()
        protected_tool = protect_web_result(result, domain_handle, vault)
        filter_ms += round((time.monotonic() - filter_started) * 1000)
        history.append(protected_tool)
        new_turns.append(
            {
                "role": "tool",
                "kind": "tool_result",
                "display": raw_result,
                "protected": protected_tool["content"],
            }
        )
    elif include_tool:
        history.append({"role": "assistant", "content": f"Tool call: {TOOL_CALL}"})
        new_turns.append(
            {
                "role": "agent",
                "kind": "tool_call",
                "display": TOOL_CALL,
                "protected": TOOL_CALL,
            }
        )
        tool = {"role": "tool", "content": TOOL_RESULT}
        filter_started = time.monotonic()
        protected_tool = protected_message(tool, vault)
        filter_ms += round((time.monotonic() - filter_started) * 1000)
        history.append(protected_tool)
        new_turns.append(
            {
                "role": "tool",
                "kind": "tool_result",
                "display": TOOL_RESULT,
                "protected": protected_tool["content"],
            }
        )

    llm_started = time.monotonic()
    llm_url, llm_model, api_key = model_config(payload)
    outbound = model_messages(history, vault)
    raw_answer = call_llm(
        llm_url,
        llm_model,
        outbound,
        api_key=api_key or None,
        reasoning_effort=LLM_REASONING_EFFORT if llm_url == LLM_URL else None,
    )
    llm_ms = round((time.monotonic() - llm_started) * 1000)
    restored_answer = vault.restore(raw_answer)
    history.append({"role": "assistant", "content": raw_answer})
    new_turns.append(
        {
            "role": "agent",
            "kind": "message",
            "display": restored_answer,
            "protected": raw_answer,
        }
    )

    state["protected_history"] = history
    state["turns"].extend(new_turns)
    state["pending"] = None
    identity_status = identity_name_context(history, vault)
    return {
        "turns": state["turns"],
        "identity_status": identity_status,
        "person_links": trusted_person_links(identity_status, vault),
        "metrics": {
            "filter_ms": filter_ms,
            "llm_ms": llm_ms,
            "handles": handle_count(history),
            "messages": len(state["turns"]),
        },
    }


def decide_person_link(payload: dict) -> dict:
    vault, state = request_context(payload)
    candidate = payload.get("candidate_reference")
    canonical = payload.get("canonical_reference")
    context = identity_name_context(state["protected_history"], vault)
    if not any(
        item["candidate"] == candidate and item["canonical"] == canonical
        for item in context["person_links"]
    ):
        raise ValueError("person link is not a candidate in this protected conversation")
    decision = vault.decide_person_link(
        candidate,
        canonical,
        payload.get("decision"),
        evidence_source=payload.get("evidence_source"),
        resolver_identity=payload.get("resolver_identity"),
        supersedes_decision_id=payload.get("supersedes_decision_id"),
    )
    identity_status = identity_name_context(state["protected_history"], vault)
    return {
        "decision": decision,
        "identity_status": identity_status,
        "person_links": trusted_person_links(identity_status, vault),
    }


def chat(payload: dict) -> dict:
    protect_user(payload)
    return complete_chat(payload)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/status":
            return self._json(
                200,
                {
                    "privacy": service_health(f"{PRIVACY_URL}/health", "GPU · bf16"),
                    "qwen": service_health(
                        f"{urlparse(LLM_URL).scheme}://{urlparse(LLM_URL).netloc}/health",
                        "connected",
                    ),
                    "defaults": {"url": LLM_URL, "model": LLM_MODEL},
                },
            )
        if path not in STATIC_FILES:
            return self._json(404, {"error": "not found"})
        filename, content_type = STATIC_FILES[path]
        body = (DEMO_DIR / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1_000_000:
                raise ValueError("request body must be between 1 byte and 1 MB")
            payload = json.loads(self.rfile.read(length))
            if path == "/api/protect":
                return self._json(200, protect_user(payload))
            if path == "/api/complete":
                return self._json(200, complete_chat(payload))
            if path == "/api/chat":
                return self._json(200, chat(payload))
            if path == "/api/person-links/decide":
                return self._json(200, decide_person_link(payload))
            if path == "/api/reset":
                session_id = payload.get("session_id")
                for key in [key for key in conversations if key[0] == session_id]:
                    conversations.pop(key)
                return self._json(200, {"status": "reset"})
            return self._json(404, {"error": "not found"})
        except (ValueError, KeyError, json.JSONDecodeError) as error:
            self._json(400, {"error": str(error)})
        except (OSError, urllib.error.URLError) as error:
            self._json(502, {"error": f"model service unavailable: {error}"})
        except Exception as error:
            self._json(500, {"error": f"demo request failed: {error}"})

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} {format % args}")


def main():
    if not VAULT_KEY:
        raise SystemExit("PII_VAULT_KEY must be set before starting the demo UI")
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.getenv("PII_DEMO_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PII_DEMO_PORT", "8765")))
    args = parser.parse_args()
    print(f"PII Taboo available at http://{args.host}:{args.port}")
    HTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
