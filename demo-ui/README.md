# PII Taboo demo UI

Standalone side-by-side demonstration of the live PII pipeline. It imports the parent
POC guard but is not part of its execution path or a production service.

```bash
cp .env.example .env
# Generate a stable key with `openssl rand -hex 32` and paste it into .env.
python3 demo-ui/server.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765), load the synthetic scenario, and
send it. Continue chatting to see stable handles persist across user, agent, and tool
turns. Honorifics remain readable while names pair identity/role handles with atomic
name-value handles, such as `PERSON-SH-…-FN:NAME-SH-…`. The sample shows `John Blake`
and standalone `John` sharing a `NAME` handle without sharing a `PERSON` identity.
Single-token person mentions remain explicitly incomplete as
`PERSON-SH-…-UNRESOLVED:NAME-SH-…`. Emails retain independently reusable components such
as `EMAIL-SH-…-USER@EMAIL-SH-…-DOMAIN`.
Unambiguous dates use `-DAY-NUM` / `-DAY-ISO`, `-MONTH-NAME-ENG` / `-MONTH-ISO`, and
`-YEAR`, allowing Qwen to select a representation and reorder opaque components while
the presentation filter restores the corresponding values.

The User View restores PII for the authorised viewer. The LLM View shows the canonical
protected history retained for memory, logs, and cache reuse, plus a clearly labelled
UI-only identity-resolution status derived from vault-emitted opaque pairs. That status
is not the exact outbound model context: confirmed candidate links stay visible in the
UI for audit clarity but are omitted from the model context, which contains only the
canonical identity. Neither view is added to canonical history; invented pairs are
ignored without reading mapped values. The optional tool lookup adds a deterministic fake
contact lookup and synthetic result; it does not call the web.
That result declares its synthetic provenance and evidentiary scope, including that its
last-updated value is generic record metadata rather than an authority-change event.

The trusted **Resolve identities** panel stacks unresolved shared-name matches as
**Proposals**. Each proposal shows the restored candidate and canonical values together
with their opaque references, then accepts a confirmation or rejection with evidence and
resolver identity. Confirmed and rejected links move out of Proposals into recorded
decisions, where a deliberate action can supersede them. Decisions persist in the local
SQLite vault. Confirmed identities are canonicalized only in later derived LLM payloads,
while the protected transcript remains unchanged. The panel is a demo control, not an
authenticated production approval or audit system, and identity confirmation is not
evidence of authority actions or events.

The Model popover can override the configured OpenAI-compatible endpoint, API key, and
model name for the current browser tab. These values use `sessionStorage`, return to the
server-provided defaults when reset, and are cleared when the tab closes.

An explicit web-search request containing a protected email demonstrates the trusted
tool boundary: the protected lane calls `web_search(query='EMAIL-SH-…-DOMAIN')`, the
executor resolves the domain, and the result is filtered before Qwen sees it. This
dependency-free POC uses Wikipedia's Action API as its zero-key public company-profile
source, not as a production general search engine. The resolved domain is disclosed to
that external provider by design.

Sending is deliberately progressive: the restored user turn appears immediately, its
protected pair replaces a short processing state as soon as Privacy Filter returns, and
an aligned Qwen thinking row remains until the complete protected answer is available.
User, agent, and tool rows use progressively lifted lane-specific surface shades.
