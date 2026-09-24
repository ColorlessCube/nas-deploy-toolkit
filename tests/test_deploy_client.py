import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "infra/deploy/client.py"
spec = importlib.util.spec_from_file_location("deploy_client", SOURCE)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class ClientTests(unittest.TestCase):
    def test_lost_submit_response_queries_same_id_without_resubmitting(self):
        manifest = {"repository": "owner/demo", "commit": "a" * 40, "run_id": "123"}
        environment = {
            "GITHUB_REPOSITORY": manifest["repository"],
            "GITHUB_SHA": manifest["commit"],
            "GITHUB_RUN_ID": manifest["run_id"],
            "GITHUB_ACTOR": "alex",
            "GH_TOKEN": "test-secret",
        }
        replies = [
            {"id": "b" * 64},
            ConnectionError("ack lost"),
            RuntimeError("unknown_deployment"),
            {"id": "b" * 64, "status": "running", "phase": "pull"},
            {"id": "b" * 64, "status": "succeeded", "phase": "complete"},
        ]
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(client.os.environ, environment),
            patch.object(client, "call", side_effect=replies) as call,
            patch.object(client.time, "sleep"),
        ):
            directory = Path(temporary)
            receipt = directory / "receipt.json"
            client.deploy(directory, manifest, receipt)
            self.assertEqual(json.loads(receipt.read_text())["status"], "succeeded")
            self.assertNotIn("test-secret", receipt.read_text())
        requests = [item.args[1] for item in call.call_args_list]
        self.assertEqual(
            [item["action"] for item in requests], ["plan", "submit", "status", "status", "status"]
        )
        self.assertEqual({item["id"] for item in requests[2:]}, {"b" * 64})
