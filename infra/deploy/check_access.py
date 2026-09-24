"""Cloud-only denial checks for a newly installed service identity; no business writes."""

import argparse
import json
import os
import socket
import subprocess
from pathlib import Path

import client


def verify(directory, output):
    receipt = {}
    identity = client.call(directory, {"action": "inspect"})
    receipt["restricted_inspect"] = bool(identity["service"])
    commands = [["id"], [], ["nas-deploy-v1; id"], ["-s", "sftp"]]
    for name, suffix in zip(["command", "shell", "injection", "sftp"], commands, strict=True):
        argv = client.ssh_args(directory)
        if suffix and suffix[0] == "-s":
            argv.insert(1, "-s")
            suffix = suffix[1:]
        result = subprocess.run(argv + suffix, input=b"", capture_output=True, timeout=20)
        receipt[name + "_denied"] = result.returncode != 0 and b"command_denied" in result.stdout
    forwarding = client.ssh_args(directory)
    forwarding[1:1] = ["-W", os.environ["NAS_HOST"] + ":22"]
    result = subprocess.run(forwarding, input=b"", capture_output=True, timeout=20)
    receipt["forwarding_denied"] = (
        result.returncode != 0 and b"administratively prohibited" in result.stderr
    )
    result = subprocess.run(
        client.ssh_args(directory) + ["nas-deploy-v1"],
        input=b'{"action":"inspect","service":"other"}\n',
        capture_output=True,
        timeout=20,
    )
    receipt["other_service_denied"] = result.returncode == 2 and b"request_fields" in result.stdout
    # Explicit /32 routes make the router, not missing client routes, enforce isolation.
    config = (directory / "nasdeploy.conf").read_text().splitlines()
    public = next(line.split("=", 1)[1] for line in config if line.startswith("PublicKey="))
    targets = [(os.environ["NAS_HOST"], port) for port in [5433, 6379, 5001, 18080]]
    targets += [("192.168.100.1", 22), ("192.168.2.1", 22), ("10.44.10.1", 22)]
    addresses = sorted({address for address, port in targets})
    subprocess.run(
        [
            "sudo",
            "wg",
            "set",
            "nasdeploy",
            "peer",
            public,
            "allowed-ips",
            ",".join(address + "/32" for address in addresses),
        ],
        check=True,
    )
    for address in addresses:
        subprocess.run(
            ["sudo", "ip", "route", "replace", address + "/32", "dev", "nasdeploy"], check=True
        )
    for address, port in targets:
        try:
            with socket.create_connection((address, port), timeout=4):
                blocked = False
        except OSError:
            blocked = True
        receipt[f"network_{address}_{port}_denied"] = blocked
    output.write_text(
        json.dumps({"checks": receipt, "success": all(receipt.values())}, indent=2) + "\n"
    )
    if not all(receipt.values()):
        raise RuntimeError("Deployment access isolation check failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify(args.directory, args.output)
