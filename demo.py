"""Exercise the full redact -> LLM -> restore path."""

from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path

from pii_guard import PiiVault, PrivacyFilterClient, protect_messages


def load_env(path: str | Path | None = None) -> None:
    """Load the repo's dependency-free KEY=value file without overriding the shell."""
    env_path = Path(path) if path else Path(__file__).with_name(".env")
    if not env_path.exists():
        return
    for number, raw_line in enumerate(env_path.read_text().splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key.isidentifier():
            raise ValueError(f"invalid .env entry on line {number}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


load_env()


def call_llm(
    url: str,
    model: str,
    messages: list[dict],
    api_key: str | None = None,
    reasoning_effort: str | None = "low",
) -> str:
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": 1000,
    }
    if reasoning_effort:
        payload["chat_template_kwargs"] = {"reasoning_effort": reasoning_effort}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.load(response)["choices"][0]["message"]["content"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("message")
    parser.add_argument(
        "--privacy-url", default=os.getenv("PII_PRIVACY_URL", "http://127.0.0.1:8081")
    )
    parser.add_argument("--project-id", required=True)
    parser.add_argument(
        "--vault-db", default=os.getenv("PII_DEMO_VAULT_DB", ".pii-vault.sqlite3")
    )
    parser.add_argument(
        "--llm-url",
        default=os.getenv("PII_LLM_URL"),
        help="OpenAI-compatible /v1/chat/completions URL",
    )
    parser.add_argument("--llm-model", default=os.getenv("PII_LLM_MODEL", "local-model"))
    args = parser.parse_args()

    detector = PrivacyFilterClient(args.privacy_url).detect
    key = os.environ.get("PII_VAULT_KEY")
    if not key:
        parser.error("PII_VAULT_KEY must contain a stable project-vault secret")
    project_vault = PiiVault(args.vault_db, args.project_id, key)
    outbound, project_vault = protect_messages(
        [{"role": "user", "content": args.message}], detector, project_vault
    )
    print("\nOUTBOUND TO LLM (must contain no original PII)\n")
    print(json.dumps(outbound, indent=2))

    if args.llm_url:
        raw_response = call_llm(
            args.llm_url,
            args.llm_model,
            outbound,
            api_key=os.getenv("PII_LLM_API_KEY") or None,
            reasoning_effort=os.getenv("PII_LLM_REASONING_EFFORT") or None,
        )
    else:
        references = ", ".join(project_vault.values) or "no PII references"
        raw_response = f"I preserved these references: {references}."

    print("\nRAW LLM RESPONSE\n")
    print(raw_response)
    print("\nRESTORED FOR USER\n")
    print(project_vault.restore(raw_response))


if __name__ == "__main__":
    main()
