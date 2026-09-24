"""Publish CI-tested local images as immutable build-<SHA> GHCR tags.

No rebuilding. Existing tags fail closed; a partial publish requires a new commit.
Version-tag releases remain separate and never overwrite this namespace.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def api(path):
    request = Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError("Package metadata unavailable") from None


def private_package_after_push(path):
    """GHCR package metadata may lag an accepted first push briefly."""
    for delay in (1, 2, 4, 8, 16):
        package = api(path)
        if package:
            if package.get("visibility") != "private":
                raise ValueError("Package must remain private")
            return package
        time.sleep(delay)
    return None


def publish(config, output):
    sha = os.environ["GITHUB_SHA"]
    repo = os.environ["GITHUB_REPOSITORY"]
    branch = config.get("branch", "main")
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch):
        raise ValueError("Invalid continuous-delivery branch")
    if os.environ["GITHUB_EVENT_NAME"] != "push" or os.environ["GITHUB_REF"] != "refs/heads/" + branch:
        raise ValueError("Only configured branch push may publish continuous delivery images")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid commit")
    files = {Path(name).name: Path(name).read_bytes() for name in config["compose_files"]}
    if len(files) != len(config["compose_files"]) or "deploy.json" in files or output.exists():
        raise ValueError("Deployment bundle paths must be unique and output must be new")
    tag = "build-" + sha
    for entry in config["images"].values():
        info = json.loads(subprocess.check_output(["docker", "inspect", entry["local"]]))[0]
        labels = info["Config"].get("Labels") or {}
        if (
            info["Os"] + "/" + info["Architecture"] != "linux/amd64"
            or labels.get("org.opencontainers.image.revision") != sha
            or labels.get("org.opencontainers.image.source") != "https://github.com/" + repo
        ):
            raise ValueError("Image source/platform differs from tested commit")
        scope = "orgs" if os.environ["OWNER_TYPE"] == "Organization" else "users"
        owner, name = entry["repository"].removeprefix("ghcr.io/").split("/")
        path = "/" + scope + "/" + owner + "/packages/container/" + name
        entry["package_path"] = path
        package = api(path)
        if package:
            if package["visibility"] != "private":
                raise ValueError("Package must remain private")
            for page in range(1, 101):
                versions = api(path + "/versions?per_page=100&page=" + str(page))
                if not isinstance(versions, list):
                    raise ValueError("Could not verify tags")
                if any(tag in v["metadata"]["container"]["tags"] for v in versions):
                    raise ValueError("Immutable build tag already exists; refusing overwrite")
                if len(versions) < 100:
                    break
            else:
                raise ValueError("Too many versions to verify")
    images = {}
    for key, entry in config["images"].items():
        reference = entry["repository"] + ":" + tag
        subprocess.run(["docker", "tag", entry["local"], reference], check=True)
        subprocess.run(["docker", "push", reference], check=True)
        info = json.loads(subprocess.check_output(["docker", "inspect", reference]))[0]
        digests = [
            x
            for x in info["RepoDigests"]
            if re.fullmatch(re.escape(entry["repository"]) + r"@sha256:[0-9a-f]{64}", x)
        ]
        package = private_package_after_push(entry["package_path"])
        if len(digests) != 1 or not package:
            raise ValueError("Published image could not be verified")
        images[key] = digests[0]
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}
    baseline = hashlib.sha256(
        json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    output.mkdir(parents=True)
    for name, content in files.items():
        (output / name).write_bytes(content)
    (output / "deploy.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "service": config["service"],
                "repository": repo,
                "commit": sha,
                "run_id": os.environ["GITHUB_RUN_ID"],
                "baseline": baseline,
                "images": images,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    publish(json.loads(args.config.read_text()), args.output)
