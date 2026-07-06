import hashlib
import hmac
import importlib
import io
import json
import os
import sys
import tempfile
import unittest


def import_adapter(state_dir, webhook_secret="test-webhook-secret"):
    os.environ["COVEN_GITHUB_STATE_DIR"] = str(state_dir)
    os.environ["COVEN_GITHUB_POLICY_PATH"] = str(state_dir / "policy.json")
    os.environ.pop("WEBHOOK_SECRET", None)
    os.environ["GITHUB_WEBHOOK_SECRET"] = webhook_secret
    sys.modules.pop("coven_github_adapter", None)
    return importlib.import_module("coven_github_adapter")


def import_adapter_with_legacy_secret(state_dir, webhook_secret="legacy-webhook-secret"):
    os.environ["COVEN_GITHUB_STATE_DIR"] = str(state_dir)
    os.environ["COVEN_GITHUB_POLICY_PATH"] = str(state_dir / "policy.json")
    os.environ.pop("GITHUB_WEBHOOK_SECRET", None)
    os.environ["WEBHOOK_SECRET"] = webhook_secret
    sys.modules.pop("coven_github_adapter", None)
    return importlib.import_module("coven_github_adapter")


def signature(secret, body):
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return "sha256=" + digest


class WebhookAdapterTests(unittest.TestCase):
    def call_app(self, adapter, body, headers=None, content_length="auto"):
        headers = headers or {}
        status_headers = []
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/webhook",
            "wsgi.input": io.BytesIO(body),
        }
        if content_length == "auto":
            environ["CONTENT_LENGTH"] = str(len(body))
        elif content_length is not None:
            environ["CONTENT_LENGTH"] = str(content_length)
        for name, value in headers.items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value

        def start_response(status, response_headers):
            status_headers.append((status, response_headers))

        response = b"".join(adapter.application(environ, start_response))
        status = status_headers[0][0]
        return status, json.loads(response.decode("utf-8"))

    def test_webhook_rejects_missing_and_invalid_signatures(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            adapter = import_adapter(Path(tmp))
            body = b'{"zen":"Keep it logically awesome."}'

            missing_status, missing_payload = self.call_app(
                adapter,
                body,
                {"X-GitHub-Event": "ping", "X-GitHub-Delivery": "delivery-1"},
            )
            self.assertEqual(missing_status, "401 Unauthorized")
            self.assertEqual(missing_payload["error"], "missing signature")

            invalid_status, invalid_payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-2",
                    "X-Hub-Signature-256": "sha256=deadbeef",
                },
            )
            self.assertEqual(invalid_status, "401 Unauthorized")
            self.assertEqual(invalid_payload["error"], "invalid signature")

    def test_webhook_accepts_valid_signed_ping_without_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            secret = "valid-webhook-secret"
            adapter = import_adapter(Path(tmp), secret)
            body = b'{"zen":"Keep it logically awesome."}'

            status, payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-3",
                    "X-Hub-Signature-256": signature(secret, body),
                },
            )

            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["action"], "ignored")
            self.assertEqual(payload["reason"], "no_policy_for_installation_repo")

    def test_webhook_reads_body_when_content_length_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            secret = "missing-length-secret"
            adapter = import_adapter(Path(tmp), secret)
            body = b'{"zen":"Keep it logically awesome."}'

            status, payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-missing-length",
                    "X-Hub-Signature-256": signature(secret, body),
                },
                content_length=None,
            )

            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])

    def test_webhook_reads_body_when_content_length_is_unparsable(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            secret = "bad-length-secret"
            adapter = import_adapter(Path(tmp), secret)
            body = b'{"zen":"Keep it logically awesome."}'

            status, payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-bad-length",
                    "X-Hub-Signature-256": signature(secret, body),
                },
                content_length="not-a-number",
            )

            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])

    def test_webhook_treats_zero_content_length_as_empty_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            secret = "zero-length-secret"
            adapter = import_adapter(Path(tmp), secret)

            status, payload = self.call_app(
                adapter,
                b'{"zen":"Keep it logically awesome."}',
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-zero-length",
                    "X-Hub-Signature-256": signature(secret, b""),
                },
                content_length=0,
            )

            self.assertEqual(status, "400 Bad Request")
            self.assertEqual(payload["error"], "invalid json")

    def test_webhook_rejects_oversized_content_length_before_signature_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            adapter = import_adapter(Path(tmp))
            status, payload = self.call_app(
                adapter,
                b"",
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-large-body",
                    "X-Hub-Signature-256": "sha256=deadbeef",
                },
                content_length=10 * 1024 * 1024 + 1,
            )

            self.assertEqual(status, "413 Payload Too Large")
            self.assertEqual(payload["error"], "payload too large")

    def test_webhook_signature_allows_surrounding_whitespace(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            secret = "whitespace-secret"
            adapter = import_adapter(Path(tmp), secret)
            body = b'{"zen":"Keep it logically awesome."}'

            status, payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-whitespace-signature",
                    "X-Hub-Signature-256": " " + signature(secret, body) + " ",
                },
            )

            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])

    def test_webhook_reports_missing_secret_as_server_misconfiguration(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            adapter = import_adapter(Path(tmp), "")
            body = b'{"zen":"Keep it logically awesome."}'

            status, payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-missing-secret",
                    "X-Hub-Signature-256": signature("ignored", body),
                },
            )

            self.assertEqual(status, "500 Internal Server Error")
            self.assertEqual(payload["error"], "webhook secret not configured")

    def test_webhook_secret_supports_smoke_script_environment_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            secret = "legacy-webhook-secret"
            adapter = import_adapter_with_legacy_secret(Path(tmp), secret)
            body = b'{"zen":"Keep it logically awesome."}'

            status, payload = self.call_app(
                adapter,
                body,
                {
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "delivery-legacy",
                    "X-Hub-Signature-256": signature(secret, body),
                },
            )

            self.assertEqual(status, "200 OK")
            self.assertTrue(payload["ok"])

    def test_missing_familiar_policy_does_not_fall_back_to_hardcoded_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path

            adapter = import_adapter(Path(tmp))
            task = adapter.build_task_from_event(
                "issues",
                "delivery-4",
                {
                    "action": "opened",
                    "installation": {"id": 111},
                    "repository": {
                        "id": 222,
                        "full_name": "OpenCoven/example",
                        "clone_url": "https://github.com/OpenCoven/example.git",
                        "default_branch": "main",
                    },
                    "issue": {"number": 7, "title": "Fix it", "body": "Please fix it."},
                },
                {
                    "trigger_labels": ["coven:fix"],
                    "bot_usernames": ["coven-github[bot]"],
                    "publication": {"mode": "record_only"},
                },
            )

            self.assertEqual(task["state"], "ignored")
            self.assertEqual(task["ignored_reason"], "missing_familiar_policy")


if __name__ == "__main__":
    unittest.main()
