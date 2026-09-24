"""Isolated fixture proof: lose the SSH acknowledgement, recover by ID, replay once.

Only accepts deploy-fixture. Never invokes a production service or arbitrary command.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client  # noqa: E402


def verify(directory, manifest, receipt, output):
    if manifest["service"] != "deploy-fixture":
        raise ValueError("Recovery proof is restricted to the isolated fixture")
    with tempfile.TemporaryDirectory(dir=directory) as docker_config:
        environment = {**os.environ, "DOCKER_CONFIG": docker_config}
        commands = [
            [
                "docker",
                "login",
                "ghcr.io",
                "--username",
                os.environ["GITHUB_ACTOR"],
                "--password-stdin",
            ]
        ]
        commands += [["docker", "manifest", "inspect", ref] for ref in manifest["images"].values()]
        for command in commands:
            result = subprocess.run(
                command,
                input=os.environ["GH_TOKEN"].encode() if command[1] == "login" else None,
                capture_output=True,
                timeout=90,
                env=environment,
            )
            if result.returncode:
                raise RuntimeError("Cloud deployment token could not read the fixture registry")
    original_call = client.call
    discarded = False

    def lose_ack(connection, request):
        nonlocal discarded
        if request["action"] == "submit":
            # Close the SSH session and deliberately discard its acknowledgement.
            # No polling connection stays attached to the NAS executor.
            result = subprocess.run(
                client.ssh_args(connection) + ["nas-deploy-v1"],
                input=json.dumps(request).encode() + b"\n",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=180,
            )
            if result.returncode:
                raise RuntimeError("Fixture submission rejected")
            discarded = True
            raise ConnectionError("Deliberately discarded fixture acknowledgement")
        return original_call(connection, request)

    client.call = lose_ack
    try:
        client.deploy(directory, manifest, receipt)
    finally:
        client.call = original_call
    first = json.loads(receipt.read_text())
    replay = original_call(
        directory,
        {
            "action": "submit",
            "manifest": manifest,
            "credentials": {
                "username": os.environ["GITHUB_ACTOR"],
                "token": os.environ["GH_TOKEN"],
            },
        },
    )
    checks = {
        "cloud_job_token_registry_read": True,
        "acknowledgement_discarded": discarded,
        "detached_execution_succeeded": first["status"] == "succeeded",
        "replay_returned_identical_receipt": first == replay,
    }
    output.write_text(
        json.dumps({"checks": checks, "success": all(checks.values())}, indent=2) + "\n"
    )
    if not all(checks.values()):
        raise RuntimeError("Fixture recovery proof failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify(args.directory, json.loads(args.manifest.read_text()), args.receipt, args.output)
