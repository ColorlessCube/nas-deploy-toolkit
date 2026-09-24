import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError, URLError

SOURCE = Path(__file__).resolve().parents[1] / "infra/deploy/agent.py"
spec = importlib.util.spec_from_file_location("nas_deployment", SOURCE)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        directory = self.root / "services/demo"
        directory.mkdir(parents=True)
        (directory / "compose.yaml").write_text("services: {}\n")
        self.current = self.root / "current.env"
        self.current.write_text("IMAGE=previous\n")
        self.policy = {
            "service": "demo",
            "repository": "ColorlessCube/demo",
            "enabled": True,
            "compose_files": ["compose.yaml"],
            "images": {"IMAGE": "ghcr.io/colorlesscube/demo"},
            "current_images": str(self.current),
            "docker": "docker",
            "stop_order": ["web"],
            "start_groups": [["web"]],
            "services": ["web"],
            "hooks": {"backup": ["backup"]},
            "branch": "main",
            "workflow": ".github/workflows/publish.yml",
            "required_jobs": ["verify", "publish"],
        }
        (directory / "policy.json").write_text(json.dumps(self.policy))
        self.engine = agent.Engine(self.root, "demo")
        self.manifest = {
            "schema": 1,
            "service": "demo",
            "repository": "ColorlessCube/demo",
            "commit": "a" * 40,
            "baseline": self.engine.approved,
            "images": {"IMAGE": "ghcr.io/colorlesscube/demo@sha256:" + "b" * 64},
            "run_id": "123",
        }

    def test_manifest_rejects_cross_service_paths_floating_tags_and_changed_baseline(self):
        for changes in [
            {"service": "ass"},
            {"service": "../ass"},
            {"repository": "owner/other"},
            {"compose": "arbitrary"},
            {"baseline": "0" * 64},
            {"commit": "main"},
            {"images": {"IMAGE": "ghcr.io/colorlesscube/demo:latest"}},
            {"images": {"IMAGE": "ghcr.io/other/demo@sha256:" + "b" * 64}},
            {"images": {"IMAGE": self.manifest["images"]["IMAGE"] + "\nEVIL=1"}},
        ]:
            with self.subTest(changes=changes), self.assertRaises(agent.Rejected):
                self.engine.plan({**self.manifest, **changes})

    def test_idempotency_ignores_rerun_id_but_includes_image_content(self):
        first = self.engine.plan(self.manifest)["id"]
        self.assertEqual(first, self.engine.plan({**self.manifest, "run_id": "456"})["id"])
        changed = {
            **self.manifest,
            "images": {"IMAGE": "ghcr.io/colorlesscube/demo@sha256:" + "c" * 64},
        }
        self.assertNotEqual(first, self.engine.plan(changed)["id"])

    def test_source_requires_current_branch_commit_and_successful_required_jobs(self):
        head = {"object": {"sha": self.manifest["commit"]}}
        run = {
            "head_sha": self.manifest["commit"],
            "path": self.policy["workflow"],
            "event": "push",
            "repository": {"full_name": self.policy["repository"]},
        }
        jobs = {
            "jobs": [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in ["verify", "publish"]
            ]
        }
        with patch.object(agent, "github", side_effect=[head, run, jobs]):
            agent.verify_source(self.manifest, self.policy, "secret")
        for replies in [
            [{"object": {"sha": "c" * 40}}],
            [head, {**run, "event": "pull_request"}],
            [head, run, {"jobs": jobs["jobs"][:1]}],
        ]:
            with (
                patch.object(agent, "github", side_effect=replies),
                self.assertRaises(agent.Rejected),
            ):
                agent.verify_source(self.manifest, self.policy, "secret")

    def test_source_network_failures_retry_but_permission_denial_does_not(self):
        with (
            patch.object(agent, "urlopen", side_effect=URLError("temporary")) as request,
            patch.object(agent.time, "sleep"),
            self.assertRaisesRegex(agent.Rejected, "github_verification_unavailable"),
        ):
            agent.github("/repos/owner/demo", "secret")
        self.assertEqual(request.call_count, 3)
        with (
            patch.object(
                agent, "urlopen", side_effect=HTTPError("url", 403, "denied", {}, None)
            ) as request,
            self.assertRaisesRegex(agent.Rejected, "github_verification_denied"),
        ):
            agent.github("/repos/owner/demo", "secret")
        request.assert_called_once()

    def test_registry_retries_transient_failure_without_exposing_stderr(self):
        replies = [
            SimpleNamespace(returncode=1, stderr=b"connection reset token=do-not-persist"),
            SimpleNamespace(returncode=0, stderr=b""),
        ]
        with (
            patch.object(agent.subprocess, "run", side_effect=replies) as run,
            patch.object(agent.time, "sleep"),
        ):
            self.engine.registry(["docker", "pull", "image"], env=agent.BASE_ENV)
        self.assertEqual(run.call_count, 2)
        with (
            patch.object(
                agent.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=1, stderr=b"unauthorized token=do-not-persist"
                ),
            ) as run,
            self.assertRaisesRegex(agent.Rejected, "^registry_access_denied$"),
        ):
            self.engine.registry(["docker", "pull", "image"], env=agent.BASE_ENV)
        run.assert_called_once()

    def queued(self):
        identity = self.engine.plan(self.manifest)["id"]
        directory = self.engine.state / "jobs" / identity
        directory.mkdir(parents=True)
        agent.atomic_json(directory / "manifest.json", self.manifest)
        agent.atomic_json(
            directory / "receipt.json", {"id": identity, "status": "queued", "phase": "accepted"}
        )
        agent.atomic_json(self.engine.state / "latest.json", {"id": identity})
        return identity

    def test_same_request_returns_existing_receipt_while_executor_holds_lock(self):
        identity = self.queued()
        with self.engine.lock(), patch.object(agent, "verify_source") as verify:
            result = self.engine.submit(self.manifest, {"username": "alex", "token": "secret"})
        self.assertEqual(identity, result["id"])
        verify.assert_not_called()

    def test_nonterminal_previous_execution_blocks_new_release_even_without_live_process(self):
        self.queued()
        changed = {**self.manifest, "commit": "c" * 40}
        with self.assertRaisesRegex(agent.Rejected, "service_needs_attention"):
            self.engine.submit(changed, {"username": "alex", "token": "secret"})

    def execute_failure(self, failure):
        identity = self.queued()
        self.engine.policy["migration_service"] = "migrate"
        stages = []

        def command(*args, **kwargs):
            stages.append(args)
            if failure == "pull" and args[0][1] == "pull":
                raise agent.Rejected("pull_failed")
            return b""

        def compose(images, *args, **kwargs):
            stages.append(args)
            if failure == "migration" and args[0] == "run":
                raise agent.Rejected("migration_failed")

        def hook(name, *args):
            if failure == "backup" and name == "backup":
                raise agent.Rejected("backup_failed")

        def temporary(**kwargs):
            return tempfile.TemporaryDirectory(dir=self.root)

        original_temporary = tempfile.TemporaryDirectory
        with (
            patch.object(self.engine, "run", side_effect=command),
            patch.object(self.engine, "registry", side_effect=command),
            patch.object(self.engine, "compose", side_effect=compose),
            patch.object(self.engine, "hook", side_effect=hook),
            patch.object(self.engine, "verify_images"),
            patch.object(self.engine, "health"),
            patch.object(agent, "verify_source"),
            patch.object(
                agent.tempfile,
                "TemporaryDirectory",
                side_effect=lambda **kw: original_temporary(dir=self.root),
            ),
        ):
            secret = {"username": "alex", "token": "secret-not-in-receipt"}
            self.engine.execute(identity, secret)
        self.assertEqual(secret, {})
        receipt = self.engine.receipt(identity)
        self.assertNotIn("secret-not-in-receipt", json.dumps(receipt))
        return receipt, stages

    def test_pull_failure_never_stops_old_services(self):
        receipt, stages = self.execute_failure("pull")
        self.assertEqual(receipt["status"], "failed_safe")
        self.assertFalse(any(args[0] == "stop" for args in stages))
        self.assertEqual(self.current.read_text(), "IMAGE=previous\n")

    def test_backup_failure_restarts_previous_images_without_migration(self):
        receipt, stages = self.execute_failure("backup")
        self.assertTrue(receipt["previous_restored"])
        self.assertEqual(receipt["status"], "failed_safe")
        self.assertFalse(any(args[0] == "run" for args in stages))
        self.assertEqual(self.current.read_text(), "IMAGE=previous\n")

    def test_migration_failure_freezes_service_without_automatic_database_restore(self):
        receipt, stages = self.execute_failure("migration")
        self.assertEqual(receipt["status"], "needs_attention")
        self.assertFalse(any(args[0] == "up" for args in stages))

    def test_disabled_policy_and_unknown_operations_are_rejected(self):
        self.engine.policy["enabled"] = False
        with self.assertRaisesRegex(agent.Rejected, "service_disabled"):
            self.engine.submit(self.manifest, {})
        for request in [
            {"action": "exec", "command": "id"},
            {"action": "inspect", "service": "ass"},
        ]:
            with self.assertRaises(agent.Rejected):
                self.engine.dispatch(request)


if __name__ == "__main__":
    unittest.main()
