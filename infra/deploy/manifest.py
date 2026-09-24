"""Build the versioned generic manifest from published immutable image references."""

import argparse
import hashlib
import json
import os
from pathlib import Path


def write_manifest(service, images, files, output):
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    baseline = hashlib.sha256(
        json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    manifest = {
        "schema": 1,
        "service": service,
        "repository": os.environ["GITHUB_REPOSITORY"],
        "commit": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "baseline": baseline,
        "images": images,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True)
    parser.add_argument("--images-json", type=Path, required=True)
    parser.add_argument("--compose", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_manifest(
        args.service, json.loads(args.images_json.read_text()), args.compose, args.output
    )
