# Threat model

PII Taboo is a proof of a narrow boundary: replace detected PII before downstream LLM
processing, preserve stable project identity in protected text, and restore values only
inside a trusted presentation or tool boundary.

## Protected assets

- Original PII and secrets detected in newly ingested text.
- The reference-to-value map and its fingerprinting key.
- Project separation between otherwise identical values.
- Canonical protected conversation and memory content.

## Trust boundaries

The detector, vault, and restoration code are trusted. The downstream LLM, model
provider, memory engine, logs, caches, generated text, and tool responses are untrusted
until protected. A tool that receives a restored value is an explicit disclosure to that
tool and its operator.

## In-scope protections

- Stable, typed, project-scoped replacement references.
- No reverse map in the downstream model payload.
- Protected history remains protected across turns and restarts.
- Existing references are not reprocessed as new PII.
- Unknown or overlapping detector spans fail rather than silently corrupting text.

## Known limits

- Detection errors can leak PII or remove legitimate public information.
- Context and quasi-identifiers may identify somebody without containing a detected span.
- Stable references permit correlation inside their project scope.
- The LLM can alter, truncate, invent, or omit references.
- The SQLite demonstration vault is not encrypted and has no user authorisation model.
- Local file permissions do not protect against a compromised host or privileged user.
- Browser overrides place an optional API key in tab-scoped session storage.
- Restoration does not itself prove that the viewer or tool is authorised.
- The included web-search demonstration intentionally reveals its resolved query to the
  configured external provider.

## Production requirements

- Evaluate the detector on representative languages, domains, and adversarial inputs.
- Fail closed when detection, persistence, restoration, or policy evaluation is
  unavailable.
- Authenticate and encrypt every service-to-service connection.
- Store mappings in an encrypted vault with tenant isolation, key rotation, retention,
  deletion, backup, and recovery controls.
- Authorise every reveal and tool disclosure using the platform's authoritative access
  decision; never distribute a reusable master decryption key to clients.
- Audit reference IDs, caller, purpose, policy, and result without logging plaintext.
- Keep protected content canonical and restore only ephemeral presentation copies.
- Consider short-lived transport aliases when a third-party model should not correlate
  stable project references across requests.
- Treat unresolved or foreign-project references as errors before executing side effects.

Do not report vulnerabilities using real personal information. Before publishing this
repository, enable a private security-reporting channel for maintainers.
