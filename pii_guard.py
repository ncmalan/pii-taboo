"""Minimal reversible PII guard with project-stable typed references."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import unicodedata
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


SYSTEM_GUIDANCE = (
    "Personal information has been replaced with stable, typed project references such "
    "as PERSON-SH-ID, EMAIL-SH-ID, or PHONE-SH-ID. The same reference denotes the same "
    "project value across messages. Person name components use paired references such as "
    "PERSON-SH-ID-FN:NAME-SH-ID. The PERSON reference carries identity and component role; "
    "the NAME reference carries only normalized atomic name equality. The same NAME "
    "reference can occur with different PERSON identities and does not prove that the "
    "people are the same. Matching NAME references may raise an identity question, but "
    "never merge PERSON identities, transfer actions, roles, or authority, or privilege "
    "one candidate. State relevant protected name-text matches while keeping the identity "
    "relationship unresolved. Treat exact equality only when NAME references repeat; do "
    "not request or infer plaintext or reverse-map values. A PERSON reference ending in "
    "-UNRESOLVED is a distinct mention "
    "whose first-name, last-name, or mononym role is unknown; preserve the complete pair "
    "unchanged and never convert it to -FN or -LN. Full person references use -FN or -LN "
    "for the first-name or last-name component. Prefer the -FN pair alone for "
    "a natural conversational greeting; use a visible title plus -LN for formal address, "
    "and use both only when the full name is materially needed. Email addresses are represented "
    "as EMAIL-SH-ID-USER@EMAIL-SH-ID-DOMAIN so either component can be reused without "
    "revealing it. Unambiguous dates use -DAY-NUM or -DAY-ISO, -MONTH-NAME-ENG or "
    "-MONTH-ISO, and -YEAR. You may switch between those variants on the same base date "
    "and reorder or separate components to satisfy an explicit format request. For example, "
    "convert DATE-SH-ID-DAY-NUM DATE-SH-ID-MONTH-NAME-ENG DATE-SH-ID-YEAR to dd/mm/yyyy "
    "as DATE-SH-ID-DAY-ISO/DATE-SH-ID-MONTH-ISO/DATE-SH-ID-YEAR. This suffix substitution "
    "is the only exception to preserving references character-for-character; never change "
    "the base ID. An atomic DATE reference cannot be reformatted. Use the type as semantic "
    "context and never guess an original value. Tool calls may pass protected references; "
    "the trusted tool boundary resolves authorized arguments and protects results before "
    "returning them."
)
PROTECTED_EVIDENCE_CONTRACT = {
    "type": "protected_evidence_contract",
    "conclusions": {
        "verified_fact": (
            "assert a contradiction only when declared semantics and provenance identify "
            "authoritative evidence for the relevant identities and actions"
        ),
        "unresolved_question": (
            "when authoritative evidence is absent, state what must be verified before "
            "reaching a conclusion"
        ),
        "hypothesis": "label explicitly and never present as a verified fact",
    },
    "field_semantics": {
        "contact_record.last_updated": (
            "generic record-maintenance metadata; not authority-change evidence and "
            "never evidence of revocation or reassignment"
        ),
    },
}

_TYPE_NAMES = {
    "account_number": "ACCOUNT",
    "private_address": "ADDRESS",
    "private_email": "EMAIL",
    "private_name": "NAME",
    "private_person": "PERSON",
    "private_phone": "PHONE",
    "private_url": "URL",
    "private_date": "DATE",
    "secret": "SECRET",
}
_REFERENCE_ID = r"[A-Z2-7]{12}"
_PERSON_NAME_REFERENCE = (
    rf"PERSON-SH-{_REFERENCE_ID}-(?:FN|LN|UNRESOLVED):NAME-SH-{_REFERENCE_ID}"
)
_PERSON_NAME_RELATION_RE = re.compile(
    rf"\b(?P<person>PERSON-SH-{_REFERENCE_ID})-"
    rf"(?P<role>FN|LN|UNRESOLVED):(?P<name>NAME-SH-{_REFERENCE_ID})\b"
)
_ATOMIC_REFERENCE = (
    rf"(?:{'|'.join(_TYPE_NAMES.values())})-SH-{_REFERENCE_ID}"
    r"(?:-(?:MONTH-NAME-ENG|MONTH-ISO|DAY-NUM|DAY-ISO|UNRESOLVED|FN|LN|USER|DOMAIN|DAY|MONTH|YEAR))?"
)
_REFERENCE_RE = re.compile(
    rf"\b(?:{_PERSON_NAME_REFERENCE}|{_ATOMIC_REFERENCE})\b"
)
MAX_CHUNK_BYTES = 7_500
CHUNK_OVERLAP_CHARS = 512
_SQLITE_LOOKUP_CHUNK_SIZE = 500
_HONORIFICS = {
    "mr",
    "mrs",
    "ms",
    "miss",
    "dr",
    "prof",
    "professor",
    "sir",
    "dame",
}


@dataclass(frozen=True)
class Span:
    label: str
    start: int
    end: int
    score: float = 1.0


class PrivacyFilterClient:
    """Client for the companion DGX /detect endpoint."""

    def __init__(self, base_url: str, timeout: float = 10.0):
        self.url = f"{base_url.rstrip('/')}/detect"
        self.timeout = timeout

    def detect(self, text: str) -> list[Span]:
        spans = [
            Span(span.label, span.start + offset, span.end + offset, span.score)
            for offset, chunk in _chunk_text(text)
            for span in self._detect_chunk(chunk)
        ]
        return _merge_overlapping_spans(spans)

    def _detect_chunk(self, text: str) -> list[Span]:
        request = urllib.request.Request(
            self.url,
            data=json.dumps({"text": text}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.load(response)
        return [
            Span(
                label=span["label"],
                start=int(span["start"]),
                end=int(span["end"]),
                score=float(span["score"]),
            )
            for span in payload["spans"]
        ]


class PiiVault:
    """Persistent pseudonym registry shared by every user of one project."""

    def __init__(self, db_path: str, project_id: str, secret_key: str | bytes):
        if not project_id.strip():
            raise ValueError("project_id must not be empty")
        key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        if len(key) < 32:
            raise ValueError("secret_key must be at least 32 bytes")
        self.db_path = db_path
        self.project_id = project_id
        self._key = key
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS pii_entities (
                    project_id TEXT NOT NULL,
                    reference TEXT NOT NULL,
                    pii_type TEXT NOT NULL,
                    canonical_value TEXT NOT NULL,
                    PRIMARY KEY (project_id, reference)
                );
                CREATE TABLE IF NOT EXISTS pii_aliases (
                    project_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    reference TEXT NOT NULL,
                    PRIMARY KEY (project_id, fingerprint)
                );
                """
            )
        os.chmod(db_path, 0o600)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _digest(self, value: str) -> bytes:
        payload = f"{self.project_id}\0{value}".encode()
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def _fingerprint(self, pii_type: str, value: str) -> str:
        return self._digest(f"{pii_type}\0{_normalize(pii_type, value)}").hex()

    def reference(self, label: str, value: str) -> str:
        pii_type = _pii_type(label)
        fingerprint = self._fingerprint(pii_type, value)
        fingerprints = [fingerprint]
        if pii_type == "DATE":
            legacy = self._digest(f"{pii_type}\0{_clean(value)}").hex()
            if legacy != fingerprint:
                fingerprints.append(legacy)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for candidate in fingerprints:
                row = connection.execute(
                    "SELECT reference FROM pii_aliases WHERE project_id = ? AND fingerprint = ?",
                    (self.project_id, candidate),
                ).fetchone()
                if row:
                    if candidate != fingerprint:
                        connection.execute(
                            "INSERT OR IGNORE INTO pii_aliases VALUES (?, ?, ?)",
                            (self.project_id, fingerprint, row[0]),
                        )
                    return row[0]

            token = base64.b32encode(self._digest(fingerprint)).decode()[:12]
            reference = f"{pii_type}-SH-{token}"
            connection.execute(
                "INSERT INTO pii_entities VALUES (?, ?, ?, ?)",
                (self.project_id, reference, pii_type, value.strip()),
            )
            connection.execute(
                "INSERT INTO pii_aliases VALUES (?, ?, ?)",
                (self.project_id, fingerprint, reference),
            )
            return reference

    def replacement(self, label: str, value: str) -> str:
        """Return one or more typed handles suitable for the protected text."""
        pii_type = _pii_type(label)
        reference = self.reference(label, value)
        prefix = ""
        separators = (" ",)
        stored_components = None
        name_components = None
        if pii_type == "PERSON" and (person_parts := _person_parts(value)):
            # ponytail: first-token/remainder heuristic; use canonical name components
            # from entity reconciliation when names beyond this POC matter.
            prefix, first_name, last_name = person_parts
            components = (
                (("FN", first_name), ("LN", last_name))
                if last_name
                else (("UNRESOLVED", first_name),)
            )
            name_components = tuple(
                (suffix, component, self.reference("private_name", component))
                for suffix, component in components
            )
        elif pii_type == "EMAIL" and (email_parts := _email_parts(value)):
            components = (("USER", email_parts[0]), ("DOMAIN", email_parts[1]))
            separators = ("@",)
        elif pii_type == "DATE" and (date_parts := _date_parts(value)):
            components, separators, stored_components = date_parts
        else:
            return reference
        with self._connect() as connection:
            connection.executemany(
                "INSERT OR IGNORE INTO pii_entities VALUES (?, ?, ?, ?)",
                (
                    (self.project_id, f"{reference}-{suffix}", pii_type, component)
                    for suffix, component in stored_components or components
                ),
            )
            if name_components:
                connection.executemany(
                    "INSERT OR IGNORE INTO pii_entities VALUES (?, ?, ?, ?)",
                    (
                        (
                            self.project_id,
                            f"{reference}-{suffix}:{name_reference}",
                            pii_type,
                            component,
                        )
                        for suffix, component, name_reference in name_components
                    ),
                )
        component_handles = (
            [
                f"{reference}-{suffix}:{name_reference}"
                for suffix, _, name_reference in name_components
            ]
            if name_components
            else [f"{reference}-{suffix}" for suffix, _ in components]
        )
        handles = component_handles[0]
        for separator, handle in zip(separators, component_handles[1:]):
            handles += separator + handle
        return f"{prefix} {handles}" if prefix else handles

    def add_alias(self, reference: str, label: str, value: str) -> None:
        """Link a reconciled spelling/format variant to an existing reference."""
        pii_type = _pii_type(label)
        fingerprint = self._fingerprint(pii_type, value)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            entity = connection.execute(
                "SELECT pii_type FROM pii_entities WHERE project_id = ? AND reference = ?",
                (self.project_id, reference),
            ).fetchone()
            if not entity:
                raise ValueError(f"unknown project reference: {reference}")
            if entity[0] != pii_type:
                raise ValueError(f"alias type {pii_type} does not match {entity[0]}")
            existing = connection.execute(
                "SELECT reference FROM pii_aliases WHERE project_id = ? AND fingerprint = ?",
                (self.project_id, fingerprint),
            ).fetchone()
            if existing and existing[0] != reference:
                raise ValueError("alias is already linked to another reference")
            connection.execute(
                "INSERT OR IGNORE INTO pii_aliases VALUES (?, ?, ?)",
                (self.project_id, fingerprint, reference),
            )

    def restore(self, text: str) -> str:
        references = set(_REFERENCE_RE.findall(text))
        if not references:
            return text
        placeholders = ",".join("?" for _ in references)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT reference, canonical_value FROM pii_entities WHERE project_id = ? "
                f"AND reference IN ({placeholders})",
                (self.project_id, *references),
            ).fetchall()
        for reference, value in sorted(rows, key=lambda row: len(row[0]), reverse=True):
            text = text.replace(reference, value)
        return text

    @property
    def values(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT reference, canonical_value FROM pii_entities WHERE project_id = ? "
                "ORDER BY reference",
                (self.project_id,),
            ).fetchall()
        return dict(rows)


def _pii_type(label: str) -> str:
    label = re.sub(r"^[BIES]-", "", label).lower()
    try:
        return _TYPE_NAMES[label]
    except KeyError as error:
        raise ValueError(f"unknown PII type: {label}") from error


def _normalize(pii_type: str, value: str) -> str:
    value = _clean(value)
    if pii_type == "PHONE":
        return re.sub(r"\D", "", value)
    if pii_type == "ACCOUNT":
        return re.sub(r"[^\w]", "", value).casefold()
    if pii_type == "PERSON":
        parts = _person_parts(value)
        return (
            " ".join(part for part in parts[1:] if part).casefold()
            if parts
            else value.casefold()
        )
    if pii_type in {"EMAIL", "ADDRESS", "NAME"}:
        return value.casefold()
    if pii_type == "DATE" and (parts := _date_parts(value)):
        values = dict(parts[2])
        return f"{values['YEAR']}-{values['MONTH-ISO']}-{values['DAY-ISO']}"
    return value


def _clean(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _person_parts(value: str) -> tuple[str, str, str | None] | None:
    parts = value.strip().split()
    title = ""
    if parts and parts[0].rstrip(".").casefold() in _HONORIFICS:
        title = parts.pop(0)
    if not parts:
        return None
    return title, parts[0], " ".join(parts[1:]) or None


def _email_parts(value: str) -> tuple[str, str] | None:
    username, separator, domain = value.strip().rpartition("@")
    return (username, domain) if username and separator and domain else None


def _date_parts(
    value: str,
) -> tuple[
    tuple[tuple[str, str], ...],
    tuple[str, ...],
    tuple[tuple[str, str], ...],
] | None:
    formats = (
        ("%d %B %Y", ("DAY-NUM", "MONTH-NAME-ENG", "YEAR"), (" ", " ")),
        ("%d %b %Y", ("DAY-NUM", "MONTH-NAME-ENG", "YEAR"), (" ", " ")),
        ("%B %d, %Y", ("MONTH-NAME-ENG", "DAY-NUM", "YEAR"), (" ", ", ")),
        ("%b %d, %Y", ("MONTH-NAME-ENG", "DAY-NUM", "YEAR"), (" ", ", ")),
        ("%Y-%m-%d", ("YEAR", "MONTH-ISO", "DAY-ISO"), ("-", "-")),
    )
    for date_format, order, separators in formats:
        try:
            parsed = datetime.strptime(value.strip(), date_format)
        except ValueError:
            continue
        variants = {
            "DAY-NUM": str(parsed.day),
            "DAY-ISO": f"{parsed.day:02d}",
            "MONTH-NAME-ENG": parsed.strftime("%B"),
            "MONTH-ISO": f"{parsed.month:02d}",
            "YEAR": f"{parsed.year:04d}",
            # Legacy component handles remain reversible for existing protected memory.
            "DAY": f"{parsed.day:02d}",
            "MONTH": f"{parsed.month:02d}",
        }
        return (
            tuple((suffix, variants[suffix]) for suffix in order),
            separators,
            tuple(variants.items()),
        )
    return None


def _chunk_text(text: str) -> Iterable[tuple[int, str]]:
    start = 0
    while start < len(text):
        low, high, end = start + 1, len(text), start
        while low <= high:
            middle = (low + high) // 2
            if len(text[start:middle].encode()) <= MAX_CHUNK_BYTES:
                end = middle
                low = middle + 1
            else:
                high = middle - 1

        if end < len(text):
            floor = max(start + CHUNK_OVERLAP_CHARS + 1, end - 1_000)
            boundary = max(
                text.rfind("\n\n", floor, end),
                text.rfind("\n", floor, end),
                text.rfind(" ", floor, end),
            )
            if boundary >= floor:
                end = boundary + 1

        yield start, text[start:end]
        if end == len(text):
            break
        start = end - CHUNK_OVERLAP_CHARS


def _merge_overlapping_spans(spans: Iterable[Span]) -> list[Span]:
    merged: list[Span] = []
    for span in sorted(spans, key=lambda item: (item.start, item.end)):
        if merged and span.start < merged[-1].end:
            previous = merged[-1]
            if (span.end - span.start, span.score) > (
                previous.end - previous.start,
                previous.score,
            ):
                merged[-1] = span
        else:
            merged.append(span)
    return merged


Detector = Callable[[str], Iterable[Span]]


def identity_name_context(messages: list[dict], vault: PiiVault) -> dict:
    """Derive an opaque identity/name-value map from already protected messages."""
    relations = {}
    for message in messages:
        content = message.get("content")
        texts = [content] if isinstance(content, str) else [
            part["text"]
            for part in content or []
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        for text in texts:
            for match in _PERSON_NAME_RELATION_RE.finditer(text):
                relations[match.group()] = (
                    match["person"], match["role"], match["name"]
                )
    known = set()
    if relations:
        references = tuple(relations)
        with vault._connect() as connection:
            for start in range(0, len(references), _SQLITE_LOOKUP_CHUNK_SIZE):
                chunk = references[start : start + _SQLITE_LOOKUP_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                known.update(
                    row[0]
                    for row in connection.execute(
                        f"SELECT reference FROM pii_entities WHERE project_id = ? "
                        f"AND reference IN ({placeholders})",
                        (vault.project_id, *chunk),
                    )
                )
    identities: dict[str, set[tuple[str, str]]] = {}
    for reference in known:
        person, role, name = relations[reference]
        identities.setdefault(person, set()).add((role, name))
    return {
        "type": "protected_identity_to_name_values",
        "identities": [
            {
                "person": person,
                "name_values": [
                    {"role": role, "name": name}
                    for role, name in sorted(name_values)
                ],
            }
            for person, name_values in sorted(identities.items())
        ],
    }


def model_messages(protected_history: list[dict], vault: PiiVault) -> list[dict]:
    """Build the request-only model payload without changing protected history."""
    context = identity_name_context(protected_history, vault)
    return [
        {"role": "system", "content": SYSTEM_GUIDANCE},
        {
            "role": "system",
            "content": json.dumps(PROTECTED_EVIDENCE_CONTRACT, sort_keys=True),
        },
        {"role": "system", "content": json.dumps(context, sort_keys=True)},
        *protected_history,
    ]


def obfuscate(text: str, detector: Detector, vault: PiiVault) -> str:
    detection_text = _REFERENCE_RE.sub(lambda match: " " * len(match.group()), text)
    spans = sorted(detector(detection_text), key=lambda span: (span.start, span.end))
    cursor = 0
    output: list[str] = []
    for span in spans:
        if not 0 <= span.start < span.end <= len(text):
            raise ValueError(f"invalid PII span: {span}")
        value = text[span.start : span.end]
        start = span.start + len(value) - len(value.lstrip())
        end = span.end - (len(value) - len(value.rstrip()))
        if start == end:
            continue
        if start < cursor:
            raise ValueError(f"overlapping PII span: {span}")
        output.extend((text[cursor:start], vault.replacement(span.label, text[start:end])))
        cursor = end
    output.append(text[cursor:])
    return "".join(output)


def protect_messages(
    messages: list[dict], detector: Detector, vault: PiiVault
) -> tuple[list[dict], PiiVault]:
    """Obfuscate conversation content using the shared project vault."""
    protected = [{"role": "system", "content": SYSTEM_GUIDANCE}]
    for message in messages:
        copy = dict(message)
        if copy.get("role") != "system":
            content = copy.get("content")
            if isinstance(content, str):
                copy["content"] = obfuscate(content, detector, vault)
            elif isinstance(content, list):
                copy["content"] = [
                    {**part, "text": obfuscate(part["text"], detector, vault)}
                    if isinstance(part, dict) and isinstance(part.get("text"), str)
                    else part
                    for part in content
                ]
        protected.append(copy)
    return protected, vault
