import json
import os
import re
import sqlite3
import tempfile
import unittest
from collections import Counter
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from demo import load_env
from pii_guard import (
    PiiVault,
    PrivacyFilterClient,
    Span,
    identity_name_context,
    model_messages,
    obfuscate,
    protect_messages,
)


class PiiGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp_dir.name) / "vault.sqlite3")
        self.key = "test-key-which-is-at-least-32-bytes-long"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_env_file_loads_without_overriding_the_shell(self):
        env_file = Path(self.temp_dir.name) / ".env"
        env_file.write_text("# local settings\nPOC_FROM_FILE='loaded'\nPOC_EXPLICIT=file\n")
        with patch.dict(os.environ, {"POC_EXPLICIT": "shell"}, clear=False):
            load_env(env_file)
            self.assertEqual(os.environ["POC_FROM_FILE"], "loaded")
            self.assertEqual(os.environ["POC_EXPLICIT"], "shell")

    def test_typed_references_survive_users_turns_and_restarts(self):
        values = {
            "Alice Smith": "private_person",
            "alice@example.com": "private_email",
        }

        def detect(text):
            return [
                Span(label, match.start(), match.end())
                for value, label in values.items()
                for match in re.finditer(value, text, re.IGNORECASE)
            ]

        first_worker = PiiVault(self.db, "project-7", self.key)
        first_messages, _ = protect_messages(
            [
                {"role": "user", "content": "Email Alice Smith at alice@example.com."},
                {
                    "role": "tool",
                    "content": "The record owner is Alice Smith (alice@example.com).",
                },
            ],
            detect,
            first_worker,
        )
        person_reference = first_worker.reference("private_person", "Alice Smith")

        second_worker = PiiVault(self.db, "project-7", self.key)
        second_messages, _ = protect_messages(
            [{"role": "assistant", "content": "I emailed ALICE SMITH."}],
            detect,
            second_worker,
        )

        self.assertRegex(person_reference, r"^PERSON-SH-[A-Z2-7]{12}$")
        self.assertIn(person_reference, str(first_messages))
        self.assertIn(person_reference, str(second_messages))
        self.assertNotIn("Alice Smith", str(first_messages))
        self.assertNotIn("alice@example.com", str(first_messages))

        protected_name = first_messages[1]["content"].split(" at ")[0].removeprefix("Email ")
        first_name_handle, last_name_handle = protected_name.split()
        self.assertEqual(first_worker.restore(first_name_handle), "Alice")
        self.assertEqual(first_worker.restore(last_name_handle), "Smith")
        self.assertTrue(first_name_handle.startswith(f"{person_reference}-FN:NAME-SH-"))
        self.assertTrue(last_name_handle.startswith(f"{person_reference}-LN:NAME-SH-"))
        self.assertEqual(second_worker.restore(person_reference), "Alice Smith")
        self.assertNotEqual(
            PiiVault(self.db, "another-project", self.key).reference(
                "private_person", "Alice Smith"
            ),
            person_reference,
        )

    def test_person_identity_is_separate_from_project_scoped_name_values(self):
        vault = PiiVault(self.db, "project-7", self.key)
        john_blake = vault.reference("private_person", "John Blake")
        john_smith = vault.reference("private_person", "John Smith")
        john_mention = vault.reference("private_person", "John")
        blake_first, blake_last = vault.replacement(
            "private_person", "John Blake"
        ).split()
        smith_first, _ = vault.replacement("private_person", "John Smith").split()
        partial = vault.replacement("private_person", "John")
        john_name = blake_first.split(":", 1)[1]

        self.assertRegex(john_name, r"^NAME-SH-[A-Z2-7]{12}$")
        self.assertEqual(blake_first, f"{john_blake}-FN:{john_name}")
        self.assertEqual(smith_first, f"{john_smith}-FN:{john_name}")
        self.assertEqual(partial, f"{john_mention}-UNRESOLVED:{john_name}")
        self.assertEqual(len({john_blake, john_smith, john_mention}), 3)
        self.assertEqual(vault.restore(john_name), "John")
        self.assertEqual(vault.restore(blake_first), "John")
        self.assertEqual(vault.restore(blake_last), "Blake")
        self.assertEqual(vault.restore(partial), "John")

        titled = vault.replacement("private_person", "Dr. Ndlovu")
        self.assertRegex(
            titled,
            r"^Dr\. PERSON-SH-[A-Z2-7]{12}-UNRESOLVED:NAME-SH-[A-Z2-7]{12}$",
        )
        self.assertEqual(vault.restore(titled), "Dr. Ndlovu")

        protected, _ = protect_messages(
            [{"role": "user", "content": "John met John Blake."}],
            lambda text: [
                Span("private_person", 0, 4),
                Span("private_person", 9, 19),
            ],
            vault,
        )
        self.assertNotIn("John", protected[-1]["content"])
        self.assertIn(john_name, protected[-1]["content"])

        restarted = PiiVault(self.db, "project-7", self.key)
        self.assertEqual(
            restarted.replacement("private_person", "John"), partial
        )
        other_project = PiiVault(self.db, "project-8", self.key)
        other_key = PiiVault(
            str(Path(self.temp_dir.name) / "other-key.sqlite3"),
            "project-7",
            "another-test-key-which-is-at-least-32-bytes",
        )
        self.assertNotEqual(
            other_project.replacement("private_person", "John").split(":", 1)[1],
            john_name,
        )
        self.assertNotEqual(
            other_key.replacement("private_person", "John").split(":", 1)[1],
            john_name,
        )
        self.assertEqual(
            vault.replacement("private_person", "JOHN").split(":", 1)[1],
            john_name,
        )

    def test_model_request_explains_zero_one_and_many_shared_name_values(self):
        cases = {
            "no match": (["Alice", "Bob"], 1),
            "one shared value": (["John Blake", "John"], 2),
            "several people sharing a value": (["John Blake", "John Smith", "John"], 3),
        }

        for number, (label, (names, shared_count)) in enumerate(cases.items()):
            with self.subTest(label):
                vault = PiiVault(self.db, f"project-{number}", self.key)
                references = [vault.replacement("private_person", name) for name in names]
                history = [{"role": "user", "content": " ".join(references)}]
                canonical = deepcopy(history)
                context = identity_name_context(history, vault)
                outbound = model_messages(history, vault)

                self.assertEqual(history, canonical)
                self.assertEqual(json.loads(outbound[2]["content"]), context)
                self.assertEqual(outbound[3:], history)
                self.assertEqual(len(context["identities"]), len(references))
                counts = Counter(
                    value["name"]
                    for identity in context["identities"]
                    for value in identity["name_values"]
                )
                self.assertEqual(max(counts.values()), shared_count)

    def test_model_request_context_is_project_scoped_restart_safe_and_value_free(self):
        first = PiiVault(self.db, "project-7", self.key)
        protected = first.replacement("private_person", "John Blake")
        standalone = first.replacement("private_person", "John")
        history = [{"role": "user", "content": f"{protected}; {standalone}"}]
        first_context = identity_name_context(history, first)

        restarted = PiiVault(self.db, "project-7", self.key)
        restarted_history = [
            {
                "role": "user",
                "content": (
                    f'{restarted.replacement("private_person", "John Blake")}; '
                    f'{restarted.replacement("private_person", "John")}'
                ),
            }
        ]
        other_project = PiiVault(self.db, "project-8", self.key)
        other_history = [
            {
                "role": "user",
                "content": other_project.replacement("private_person", "John"),
            }
        ]

        self.assertEqual(
            identity_name_context(restarted_history, restarted), first_context
        )
        self.assertNotEqual(
            identity_name_context(other_history, other_project), first_context
        )
        serialized = json.dumps(model_messages(history, first))
        self.assertNotIn("John", serialized)
        self.assertNotIn("Blake", serialized)
        self.assertIn("Matching NAME references", serialized)
        self.assertIn("never merge PERSON identities", serialized)
        self.assertIn("transfer actions, roles, or authority", serialized)

    def test_person_link_proposals_require_an_unresolved_shared_name(self):
        vault = PiiVault(self.db, "project-7", self.key)
        history = [
            {
                "role": "user",
                "content": " ".join(
                    vault.replacement("private_person", name)
                    for name in ("John Blake", "John Smith")
                ),
            }
        ]

        self.assertEqual(identity_name_context(history, vault)["person_links"], [])

    def test_confirmed_person_link_persists_and_only_changes_the_derived_request(self):
        vault = PiiVault(self.db, "project-7", self.key)
        canonical_name = vault.replacement("private_person", "John Blake")
        captured_mention = vault.replacement("private_person", "John")
        canonical = canonical_name.split("-FN:", 1)[0]
        candidate = captured_mention.split("-UNRESOLVED:", 1)[0]
        history = [
            {
                "role": "user",
                "content": f"{canonical_name} approved it; {captured_mention} stopped it.",
            }
        ]
        stored = deepcopy(history)

        decision = vault.decide_person_link(
            candidate,
            canonical,
            "confirmed",
            evidence_source="synthetic HR identity record",
            resolver_identity="demo-reviewer",
        )
        restarted = PiiVault(self.db, "project-7", self.key)
        outbound = model_messages(history, restarted)
        context = json.loads(outbound[2]["content"])
        ui_context = identity_name_context(history, restarted)

        self.assertEqual(history, stored)
        self.assertEqual(restarted.restore(history[0]["content"]), "John Blake approved it; John stopped it.")
        self.assertNotIn(candidate, json.dumps(outbound))
        self.assertIn(canonical, outbound[3]["content"])
        self.assertEqual(restarted.restore(outbound[3]["content"]), "John Blake approved it; John stopped it.")
        self.assertEqual(len(context["identities"]), 1)
        self.assertEqual(context["person_links"], [])
        self.assertEqual(ui_context["person_links"][0]["status"], "confirmed")
        self.assertEqual(ui_context["person_links"][0]["decision_id"], decision["decision_id"])
        self.assertEqual(decision["project_id"], "project-7")
        self.assertEqual(decision["evidence_source"], "synthetic HR identity record")
        self.assertEqual(decision["resolver_identity"], "demo-reviewer")
        self.assertRegex(decision["decided_at"], r"^\d{4}-\d{2}-\d{2}T")

    def test_rejected_person_link_requires_an_explicit_persistent_supersession(self):
        vault = PiiVault(self.db, "project-7", self.key)
        canonical_name = vault.replacement("private_person", "John Blake")
        captured_mention = vault.replacement("private_person", "John")
        canonical = canonical_name.split("-FN:", 1)[0]
        candidate = captured_mention.split("-UNRESOLVED:", 1)[0]
        history = [{"role": "user", "content": f"{canonical_name} {captured_mention}"}]
        rejected = vault.decide_person_link(
            candidate,
            canonical,
            "rejected",
            evidence_source="synthetic mismatch evidence",
            resolver_identity="demo-reviewer",
        )

        restarted = PiiVault(self.db, "project-7", self.key)
        rejected_context = identity_name_context(history, restarted)
        self.assertEqual(rejected_context["person_links"][0]["status"], "rejected")
        with self.assertRaisesRegex(ValueError, "supersedes"):
            restarted.decide_person_link(
                candidate,
                canonical,
                "confirmed",
                evidence_source="later synthetic evidence",
                resolver_identity="senior-reviewer",
            )

        for boolean_id in (True, False):
            with self.subTest(boolean_id=boolean_id), self.assertRaisesRegex(
                ValueError, "positive integer"
            ):
                restarted.decide_person_link(
                    candidate,
                    canonical,
                    "confirmed",
                    evidence_source="later synthetic evidence",
                    resolver_identity="senior-reviewer",
                    supersedes_decision_id=boolean_id,
                )

        confirmed = restarted.decide_person_link(
            candidate,
            canonical,
            "confirmed",
            evidence_source="later synthetic evidence",
            resolver_identity="senior-reviewer",
            supersedes_decision_id=rejected["decision_id"],
        )
        audit = restarted.person_link_audit(candidate, canonical)

        self.assertEqual(confirmed["supersedes_decision_id"], rejected["decision_id"])
        self.assertEqual([item["decision"] for item in audit], ["rejected", "confirmed"])
        self.assertEqual(
            identity_name_context(history, restarted)["person_links"][0]["status"],
            "confirmed",
        )

    def test_person_link_validation_fails_closed(self):
        vault = PiiVault(self.db, "project-7", self.key)
        first = vault.reference("private_person", "Alice Smith")
        second = vault.reference("private_person", "Alice")
        third = vault.reference("private_person", "Alice Jones")
        email = vault.reference("private_email", "alice@example.com")
        foreign = PiiVault(self.db, "project-8", self.key).reference(
            "private_person", "Alice"
        )
        fields = {
            "decision": "confirmed",
            "evidence_source": "synthetic identity record",
            "resolver_identity": "demo-reviewer",
        }

        for candidate, canonical, message in (
            (foreign, first, "cross-project"),
            (email, first, "type"),
            ("PERSON-SH-AAAAAAAAAAAA", first, "unknown"),
        ):
            with self.subTest(message), self.assertRaisesRegex(ValueError, message):
                vault.decide_person_link(candidate, canonical, **fields)

        vault.decide_person_link(second, first, **fields)
        with self.assertRaisesRegex(ValueError, "conflicting canonical"):
            vault.decide_person_link(second, third, **fields)
        with self.assertRaisesRegex(ValueError, "cycle"):
            vault.decide_person_link(first, second, **fields)

    def test_cross_project_supersession_cannot_hide_an_active_decision(self):
        vault = PiiVault(self.db, "project-7", self.key)
        candidate = vault.reference("private_person", "Alice")
        canonical = vault.reference("private_person", "Alice Smith")
        decision = vault.decide_person_link(
            candidate,
            canonical,
            "rejected",
            evidence_source="synthetic identity record",
            resolver_identity="demo-reviewer",
        )
        other = PiiVault(self.db, "project-8", self.key)
        other_candidate = other.reference("private_person", "Bob")
        other_canonical = other.reference("private_person", "Bob Smith")
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                """
                INSERT INTO person_link_decisions (
                    project_id, candidate_reference, canonical_reference, decision,
                    evidence_source, resolver_identity, decided_at,
                    supersedes_decision_id
                ) VALUES (?, ?, ?, 'rejected', 'synthetic record',
                          'demo-reviewer', '2026-08-28T00:00:00+00:00', ?)
                """,
                (
                    "project-8",
                    other_candidate,
                    other_canonical,
                    decision["decision_id"],
                ),
            )

        statuses = vault.person_link_statuses({(candidate, canonical)})

        self.assertEqual(
            statuses[(candidate, canonical)]["decision_id"], decision["decision_id"]
        )

    def test_model_request_carries_a_structured_protected_evidence_contract(self):
        vault = PiiVault(self.db, "project-7", self.key)

        contract = json.loads(model_messages([], vault)[1]["content"])

        self.assertEqual(contract["type"], "protected_evidence_contract")
        self.assertEqual(
            set(contract["conclusions"]),
            {"verified_fact", "unresolved_question", "hypothesis"},
        )
        self.assertIn(
            "relevant identities and actions",
            contract["conclusions"]["verified_fact"],
        )
        self.assertIn("contradiction", contract["conclusions"]["verified_fact"])
        self.assertIn(
            "what must be verified",
            contract["conclusions"]["unresolved_question"],
        )
        self.assertIn(
            "not authority-change evidence",
            contract["field_semantics"]["contact_record.last_updated"],
        )
        self.assertIn(
            "not evidence of authority actions",
            contract["field_semantics"]["confirmed_person_link"],
        )

    def test_model_request_ignores_invented_or_recombined_identity_pairs(self):
        vault = PiiVault(self.db, "project-7", self.key)
        john = vault.replacement("private_person", "John Blake").split()[0]
        alice = vault.replacement("private_person", "Alice")
        invented = f'{john.split(":", 1)[0]}:{alice.split(":", 1)[1]}'

        context = identity_name_context(
            [{"role": "assistant", "content": f"{john} {invented}"}], vault
        )

        self.assertEqual(len(context["identities"]), 1)
        self.assertEqual(
            context["identities"][0]["name_values"],
            [{"role": "FN", "name": john.split(":", 1)[1]}],
        )

    def test_model_request_batches_large_identity_lookup(self):
        vault = PiiVault(self.db, "project-7", self.key)
        references = [
            vault.replacement("private_person", f"Person{number}")
            for number in range(501)
        ]
        connect = sqlite3.connect

        def limited_connect(*args, **kwargs):
            connection = connect(*args, **kwargs)
            connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 501)
            return connection

        with patch("pii_guard.sqlite3.connect", side_effect=limited_connect):
            context = identity_name_context(
                [{"role": "user", "content": " ".join(references)}], vault
            )

        self.assertEqual(len(context["identities"]), len(references))
        self.assertNotIn("Person", json.dumps(context))

    def test_normalization_and_reconciled_aliases(self):
        vault = PiiVault(self.db, "project-7", self.key)
        phone = vault.reference("private_phone", "+27 82 555 0199")
        self.assertEqual(vault.reference("private_phone", "+27825550199"), phone)

        person = vault.reference("private_person", "John Blake")
        vault.add_alias(person, "private_person", "J. Blake")
        self.assertEqual(vault.reference("private_person", "J. Blake"), person)
        self.assertEqual(vault.restore(person), "John Blake")

        titled = vault.reference("private_person", "Mr. Peter Johnson")
        self.assertEqual(vault.reference("private_person", "Peter Johnson"), titled)
        titled_replacement = vault.replacement("private_person", "Mr. Peter Johnson")
        self.assertRegex(
            titled_replacement,
            rf"^Mr\. {titled}-FN:NAME-SH-[A-Z2-7]{{12}} "
            rf"{titled}-LN:NAME-SH-[A-Z2-7]{{12}}$",
        )
        self.assertEqual(vault.restore(titled_replacement), "Mr. Peter Johnson")

        email = vault.reference("private_email", "peter.johnson@example.com")
        email_replacement = vault.replacement(
            "private_email", "peter.johnson@example.com"
        )
        self.assertEqual(email_replacement, f"{email}-USER@{email}-DOMAIN")
        self.assertEqual(vault.restore(email_replacement), "peter.johnson@example.com")

        date = vault.reference("private_date", "9 April 1975")
        date_replacement = vault.replacement("private_date", "9 April 1975")
        self.assertEqual(
            date_replacement,
            f"{date}-DAY-NUM {date}-MONTH-NAME-ENG {date}-YEAR",
        )
        self.assertEqual(vault.restore(date_replacement), "9 April 1975")
        self.assertEqual(
            vault.restore(f"{date}-DAY-ISO/{date}-MONTH-ISO/{date}-YEAR"),
            "09/04/1975",
        )
        self.assertEqual(vault.reference("private_date", "1975-04-09"), date)
        self.assertEqual(
            obfuscate(
                f"Memory says {person} changed the instruction.",
                lambda text: [Span("secret", *match.span())]
                if (match := re.search(r"PERSON-SH-", text))
                else [],
                vault,
            ),
            f"Memory says {person} changed the instruction.",
        )

    def test_rejects_overlapping_spans(self):
        vault = PiiVault(self.db, "project-7", self.key)
        with self.assertRaisesRegex(ValueError, "overlapping"):
            obfuscate(
                "Alice Smith",
                lambda _: [Span("private_person", 0, 5), Span("private_person", 3, 11)],
                vault,
            )

    def test_chunks_large_inputs_and_restores_global_offsets(self):
        class FakeClient(PrivacyFilterClient):
            def __init__(self):
                self.calls = 0

            def _detect_chunk(self, text):
                self.calls += 1
                return [
                    Span("private_person", match.start(), match.end())
                    for match in re.finditer("Alice Smith", text)
                ]

        client = FakeClient()
        text = ("ordinary project context " * 500) + "Alice Smith"
        spans = client.detect(text)
        self.assertGreater(client.calls, 1)
        self.assertEqual(len(spans), 1)
        self.assertEqual(text[spans[0].start : spans[0].end], "Alice Smith")


if __name__ == "__main__":
    unittest.main()
