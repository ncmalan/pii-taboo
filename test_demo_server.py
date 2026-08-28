import copy
import importlib.util
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

    def test_completion_exposes_request_only_identity_context_to_protected_ui(self):
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
            result["model_context"], server.identity_name_context(canonical, vault)
        )
        self.assertEqual(outbound[2:], canonical)
        self.assertEqual(
            server.conversations[("session-2", "project-7")]["protected_history"][0],
            canonical[0],
        )
        self.assertNotIn(
            result["model_context"],
            server.conversations[("session-2", "project-7")]["protected_history"],
        )
        values = [
            value
            for identity in result["model_context"]["identities"]
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
        self.assertIn(
            'id="identityContext"', (server.DEMO_DIR / "index.html").read_text()
        )


if __name__ == "__main__":
    unittest.main()
