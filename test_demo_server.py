import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "pii_demo_server", Path(__file__).parent / "demo-ui/server.py"
)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class DemoServerConfigTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
