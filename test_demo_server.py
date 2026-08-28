import copy
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pii_guard import Span


spec = importlib.util.spec_from_file_location(
    "pii_demo_server", Path(__file__).parent / "demo-ui/server.py"
)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class DemoServerConfigTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = server.VAULT_DB
        self.original_key = server.VAULT_KEY
        server.VAULT_DB = str(Path(self.temp_dir.name) / "vault.sqlite3")
        server.VAULT_KEY = "test-key-which-is-at-least-32-bytes-long"
        server.conversations.clear()

    def tearDown(self):
        server.conversations.clear()
        server.VAULT_DB = self.original_db
        server.VAULT_KEY = self.original_key
        self.temp_dir.cleanup()

    def test_person_and_shared_name_value_handles_are_counted_separately(self):
        history = [
            {
                "role": "user",
                "content": (
                    "PERSON-SH-2BD262CTZIPF-FN:NAME-SH-AJD262CTZIPF and "
                    "PERSON-SH-3CD262CTZIPF-UNRESOLVED:NAME-SH-AJD262CTZIPF"
                ),
            }
        ]

        self.assertEqual(server.handle_count(history), 3)

    def test_default_api_key_is_not_sent_to_a_custom_endpoint(self):
        original_url, original_key = server.LLM_URL, server.LLM_API_KEY
        try:
            server.LLM_URL = "https://default.example/v1/chat/completions"
            server.LLM_API_KEY = "default-secret"
            self.assertEqual(server.model_config({})[2], "default-secret")
            self.assertEqual(
                server.model_config(
                    {
                        "model_config": {
                            "url": "https://custom.example/v1/chat/completions",
                            "model": "custom-model",
                            "api_key": "",
                        }
                    }
                )[2],
                "",
            )
        finally:
            server.LLM_URL, server.LLM_API_KEY = original_url, original_key

    def test_synthetic_contact_tool_describes_its_evidence_limits(self):
        result = json.loads(server.TOOL_RESULT)

        self.assertEqual(
            result["evidence"]["provenance"],
            "synthetic project contact directory",
        )
        self.assertEqual(result["last_updated"]["kind"], "record_metadata")
        self.assertIn(
            "authority revocation",
            result["last_updated"]["not_evidence_of"],
        )
        self.assertIn(
            "identity equivalence across person mentions",
            result["evidence"]["not_authoritative_for"],
        )

    def test_completion_exposes_ui_only_identity_status_to_protected_ui(self):
        payload = {
            "session_id": "session-2",
            "project_id": "project-7",
            "message": "John Blake contradicted John.",
        }

        def detect(text):
            return [
                Span("private_person", match.start(), match.end())
                for match in re.finditer(r"John Blake|John", text)
            ]

        with patch.object(server, "detector", detect):
            server.protect_user(payload)
        vault, _ = server.request_context(payload)
        canonical = copy.deepcopy(
            server.conversations[("session-2", "project-7")]["protected_history"]
        )
        with patch.object(
            server, "call_llm", return_value="Keep identity unresolved"
        ) as call:
            result = server.complete_chat(payload)

        outbound = call.call_args.args[2]
        self.assertEqual(
            result["identity_status"], server.identity_name_context(canonical, vault)
        )
        self.assertEqual(outbound[3:], canonical)
        self.assertEqual(
            server.conversations[("session-2", "project-7")]["protected_history"][0],
            canonical[0],
        )
        self.assertNotIn(
            result["identity_status"],
            server.conversations[("session-2", "project-7")]["protected_history"],
        )
        values = [
            value
            for identity in result["identity_status"]["identities"]
            for value in identity["name_values"]
        ]
        shared = {
            value["name"] for value in values if value["role"] in {"FN", "UNRESOLVED"}
        }
        self.assertEqual(len(shared), 1)
        self.assertEqual(
            {value["role"] for value in values if value["name"] in shared},
            {"FN", "UNRESOLVED"},
        )
        html = (server.DEMO_DIR / "index.html").read_text()
        self.assertIn('id="identityContext"', html)
        self.assertIn("UI-only identity status", html)
        script = (server.DEMO_DIR / "app.js").read_text()
        self.assertIn('button.setAttribute(\n        "aria-label"', script)

    def test_trusted_person_link_decision_records_audit_without_rewriting_history(self):
        payload = {
            "session_id": "session-3",
            "project_id": "project-7",
            "message": "John Blake contradicted John.",
        }

        def detect(text):
            return [
                Span("private_person", match.start(), match.end())
                for match in re.finditer(r"John Blake|John", text)
            ]

        with patch.object(server, "detector", detect):
            protected = server.protect_user(payload)
        link = protected["identity_status"]["person_links"][0]
        trusted_link = protected["person_links"][0]
        self.assertEqual(trusted_link["candidate_value"], "John")
        self.assertEqual(trusted_link["canonical_value"], "John Blake")
        self.assertNotIn("John", json.dumps(protected["identity_status"]))
        canonical_history = copy.deepcopy(
            server.conversations[("session-3", "project-7")]["protected_history"]
        )

        result = server.decide_person_link(
            {
                **payload,
                "candidate_reference": link["candidate"],
                "canonical_reference": link["canonical"],
                "decision": "confirmed",
                "evidence_source": "synthetic HR identity record",
                "resolver_identity": "demo-reviewer",
            }
        )

        self.assertEqual(result["decision"]["decision"], "confirmed")
        self.assertEqual(result["decision"]["project_id"], "project-7")
        self.assertEqual(
            result["identity_status"]["person_links"][0]["status"], "confirmed"
        )
        self.assertEqual(result["person_links"][0]["candidate_value"], "John")
        self.assertEqual(result["person_links"][0]["canonical_value"], "John Blake")
        self.assertNotIn("synthetic HR identity record", json.dumps(result["identity_status"]))
        self.assertNotIn("demo-reviewer", json.dumps(result["identity_status"]))
        self.assertEqual(
            server.conversations[("session-3", "project-7")]["protected_history"],
            canonical_history,
        )

        with patch.object(server, "call_llm", return_value=link["canonical"]) as call:
            completed = server.complete_chat(payload)
        self.assertNotIn(link["candidate"], json.dumps(call.call_args.args[2][3:]))
        self.assertEqual(completed["turns"][-1]["display"], "John Blake")


if __name__ == "__main__":
    unittest.main()
