import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "infra/deploy/publish.py"
spec = importlib.util.spec_from_file_location("deploy_publish", SOURCE)
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


class PublishTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.compose = self.root / "compose.yaml"
        self.compose.write_text("services: {}\n")
        self.output = self.root / "bundle"
        self.config = {
            "service": "demo",
            "images": {
                "IMAGE": {"local": "demo:tested", "repository": "ghcr.io/owner/demo"},
                "WEB": {"local": "web:tested", "repository": "ghcr.io/owner/web"},
            },
            "compose_files": [str(self.compose)],
        }
        self.environment = {
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REPOSITORY": "owner/demo",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "123",
            "OWNER_TYPE": "User",
        }
        self.info = {
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "Labels": {
                    "org.opencontainers.image.revision": "a" * 40,
                    "org.opencontainers.image.source": "https://github.com/owner/demo",
                }
            },
            "RepoDigests": [],
        }

    def inspect(self, command):
        info = copy.deepcopy(self.info)
        if command[-1].startswith("ghcr.io/"):
            info["RepoDigests"] = [command[-1].split(":")[0] + "@sha256:" + "b" * 64]
        return json.dumps([info]).encode()

    def test_untrusted_event_cannot_publish(self):
        for changes in [{"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/feat/x"}]:
            with (
                patch.dict(publish.os.environ, {**self.environment, **changes}),
                patch.object(publish.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                publish.publish(self.config, self.output)
            run.assert_not_called()

    def test_configured_branch_is_allowed_and_other_branches_rejected(self):
        config = {**self.config, "branch": "master"}
        environment = {**self.environment, "GITHUB_REF": "refs/heads/master"}
        with (
            patch.dict(publish.os.environ, environment),
            patch.object(publish.subprocess, "check_output", side_effect=self.inspect),
            patch.object(
                publish,
                "api",
                side_effect=[None, None, {"visibility": "private"}, {"visibility": "private"}],
            ),
            patch.object(publish.subprocess, "run"),
        ):
            publish.publish(config, self.output)
        with patch.dict(publish.os.environ, {**environment, "GITHUB_REF": "refs/heads/main"}):
            with self.assertRaises(ValueError):
                publish.publish(config, self.output)

    def test_wrong_image_revision_fails_before_any_push(self):
        self.info["Config"]["Labels"]["org.opencontainers.image.revision"] = "c" * 40
        with (
            patch.dict(publish.os.environ, self.environment),
            patch.object(publish.subprocess, "check_output", side_effect=self.inspect),
            patch.object(publish.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "source/platform"),
        ):
            publish.publish(self.config, self.output)
        run.assert_not_called()

    def test_all_packages_checked_before_pushing_any_component(self):
        for responses in [
            [{"visibility": "private"}, [], {"visibility": "public"}],
            [
                {"visibility": "private"},
                [],
                {"visibility": "private"},
                [{"metadata": {"container": {"tags": ["build-" + "a" * 40]}}}],
            ],
        ]:
            with (
                patch.dict(publish.os.environ, self.environment),
                patch.object(publish.subprocess, "check_output", side_effect=self.inspect),
                patch.object(publish, "api", side_effect=responses),
                patch.object(publish.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                publish.publish(copy.deepcopy(self.config), self.output)
            run.assert_not_called()

    def test_publish_preserves_tested_images_and_bundles_exact_compose(self):
        with (
            patch.dict(publish.os.environ, self.environment),
            patch.object(publish.subprocess, "check_output", side_effect=self.inspect),
            patch.object(
                publish,
                "api",
                side_effect=[None, None, {"visibility": "private"}, {"visibility": "private"}],
            ),
            patch.object(publish.subprocess, "run") as run,
        ):
            publish.publish(self.config, self.output)
        self.assertEqual(
            [call.args[0][1] for call in run.call_args_list], ["tag", "push", "tag", "push"]
        )
        self.assertEqual((self.output / "compose.yaml").read_bytes(), self.compose.read_bytes())
        manifest = json.loads((self.output / "deploy.json").read_text())
        hashes = {"compose.yaml": hashlib.sha256(self.compose.read_bytes()).hexdigest()}
        expected = hashlib.sha256(
            json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(manifest["baseline"], expected)
        self.assertTrue(all("@sha256:" in ref for ref in manifest["images"].values()))

    def test_missing_published_metadata_never_emits_deployment_bundle(self):
        with (
            patch.dict(publish.os.environ, self.environment),
            patch.object(publish.subprocess, "check_output", side_effect=self.inspect),
            patch.object(publish, "api", return_value=None),
            patch.object(publish.subprocess, "run"),
            self.assertRaisesRegex(ValueError, "could not be verified"),
        ):
            publish.publish(self.config, self.output)
        self.assertFalse(self.output.exists())
