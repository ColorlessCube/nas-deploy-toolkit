"""Reusable cloud client; no application dependencies, no arbitrary remote commands.

Inputs: deployment manifest and NAS_* environment; writes a sanitized receipt.
VPN config/private SSH key live only in a caller-provided temporary directory.
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import time
from pathlib import Path


def prepare(directory):
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    required = [
        "NAS_WG_PRIVATE_KEY",
        "NAS_WG_PUBLIC_KEY",
        "NAS_SSH_KEY",
        "NAS_KNOWN_HOSTS",
        "NAS_VPN_ADDRESS",
        "NAS_HOST",
        "NAS_SSH_USER",
        "NAS_VPN_ENDPOINT",
    ]
    if not all(os.environ.get(name, "").strip() for name in required):
        raise ValueError("Deployment credentials or connection settings are missing")
    for name in ["NAS_WG_PRIVATE_KEY", "NAS_WG_PUBLIC_KEY"]:
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", os.environ[name].strip()):
            raise ValueError("Invalid WireGuard key")
    address = ipaddress.IPv4Interface(os.environ["NAS_VPN_ADDRESS"])
    target = ipaddress.IPv4Address(os.environ["NAS_HOST"])
    endpoint = os.environ["NAS_VPN_ENDPOINT"]
    if address.network.prefixlen != 32 or not re.fullmatch(r"[a-zA-Z0-9.-]+:[0-9]{1,5}", endpoint):
        raise ValueError("Invalid VPN settings")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", os.environ["NAS_SSH_USER"]):
        raise ValueError("Invalid SSH user")
    (directory / "key").write_text(os.environ["NAS_SSH_KEY"].strip() + "\n")
    (directory / "known_hosts").write_text(os.environ["NAS_KNOWN_HOSTS"].strip() + "\n")
    config = (
        "[Interface]\nPrivateKey="
        + os.environ["NAS_WG_PRIVATE_KEY"].strip()
        + "\nAddress="
        + str(address)
        + "\nMTU=1420\n[Peer]\nPublicKey="
        + os.environ["NAS_WG_PUBLIC_KEY"].strip()
        + "\nAllowedIPs="
        + str(target)
        + "/32\nEndpoint="
        + endpoint
        + "\nPersistentKeepalive=25\n"
    )
    (directory / "nasdeploy.conf").write_text(config)


def ssh_args(directory):
    return [
        "ssh",
        "-F",
        "/dev/null",
        "-i",
        str(directory / "key"),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "HostKeyAlias=alex-deploy-nas",
        "-o",
        "UserKnownHostsFile=" + str(directory / "known_hosts"),
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        os.environ["NAS_SSH_USER"] + "@" + os.environ["NAS_HOST"],
    ]


def call(directory, request):
    argv = ssh_args(directory) + ["nas-deploy-v1"]
    result = subprocess.run(
        argv, input=json.dumps(request).encode() + b"\n", capture_output=True, timeout=90
    )
    try:
        response = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise ConnectionError("NAS response unavailable; deployment state may be unknown") from None
    if result.returncode != 0 or ("error" in response and "status" not in response):
        code = response.get("error", "ssh_rejected")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,80}", code):
            code = "ssh_rejected"
        raise RuntimeError(code)
    return response


def deploy(directory, manifest, receipt_path, plan_only=False):
    if (
        manifest["repository"] != os.environ["GITHUB_REPOSITORY"]
        or manifest["commit"] != os.environ["GITHUB_SHA"]
    ):
        raise ValueError("Manifest is not from this workflow commit")
    if manifest["run_id"] != os.environ["GITHUB_RUN_ID"]:
        raise ValueError("Manifest is not from this workflow run")
    plan = call(directory, {"action": "plan", "manifest": manifest})
    if plan_only:
        receipt_path.write_text(json.dumps({"mode": "plan", **plan}, indent=2) + "\n")
        return
    request = {
        "action": "submit",
        "manifest": manifest,
        "credentials": {"username": os.environ["GITHUB_ACTOR"], "token": os.environ["GH_TOKEN"]},
    }
    # A lost acknowledgement must be recovered using the deterministic plan ID.
    try:
        response = call(directory, request)
    except (ConnectionError, subprocess.TimeoutExpired):
        response = {"id": plan["id"], "status": "unknown", "phase": "submission"}
    request["credentials"].clear()
    deadline = time.monotonic() + 1500
    while response.get("status") not in {"succeeded", "failed_safe", "needs_attention"}:
        receipt_path.write_text(json.dumps(response, indent=2) + "\n")
        if time.monotonic() > deadline:
            raise RuntimeError("Deployment status unknown; query the existing ID before retrying")
        time.sleep(8)
        try:
            response = call(directory, {"action": "status", "id": plan["id"]})
        except (ConnectionError, subprocess.TimeoutExpired):
            continue
        except RuntimeError as error:
            # Verification may still be running after the submit connection timed out.
            # Keep the same ID and bounded deadline; never blindly submit a second job.
            if str(error) != "unknown_deployment":
                raise
    receipt_path.write_text(json.dumps(response, indent=2) + "\n")
    if response["status"] != "succeeded":
        raise RuntimeError("Deployment ended: " + response["status"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "inspect", "deploy", "plan", "status"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--id")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.directory)
    elif args.command in {"inspect", "status"}:
        request = {"action": args.command}
        if args.id:
            request["id"] = args.id
        print(json.dumps(call(args.directory, request)))
    else:
        deploy(
            args.directory,
            json.loads(args.manifest.read_text()),
            args.receipt,
            plan_only=args.command == "plan",
        )


if __name__ == "__main__":
    main()
