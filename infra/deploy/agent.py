"""Root-owned, service-scoped NAS deployment gateway (Python 3.8+, stdlib only).

SSH accepts only `nas-deploy-v1`, with one bounded JSON request on stdin.
Install this file and policies as root; never accept scripts, paths or Compose from CI.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path("/volume4/docker/alex-deploy")
PROGRAM = Path("/usr/local/libexec/alex-deploy/agent.py")
NAME = re.compile(r"[a-z][a-z0-9-]{0,39}")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TERMINAL = {"succeeded", "failed_safe", "needs_attention"}
BASE_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


class Rejected(Exception):
    """Only fixed, non-sensitive error codes may cross the SSH boundary."""


def require(condition, code):
    if not condition:
        raise Rejected(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def atomic_json(path, value):
    atomic_bytes(path, canonical(value) + b"\n")


def atomic_bytes(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".new-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def trusted(path):
    info = path.lstat()
    require(
        not path.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
        "untrusted_installation",
    )


def baseline(directory, files):
    data = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in files}
    return hashlib.sha256(canonical(data)).hexdigest()


def read_request():
    # One line, no subsequent stdin is consumed by a subprocess; no unbounded read or idle wait.
    result = bytearray()
    deadline = time.monotonic() + 15
    while b"\n" not in result and len(result) <= 65536:
        remaining = deadline - time.monotonic()
        require(
            remaining > 0 and select.select([sys.stdin], [], [], remaining)[0], "request_timeout"
        )
        chunk = os.read(sys.stdin.fileno(), 4096)
        if not chunk:
            break
        result.extend(chunk)
    require(0 < len(result) <= 65536, "request_size")
    try:
        value = json.loads(result)
    except (ValueError, UnicodeError):
        raise Rejected("invalid_json") from None
    require(isinstance(value, dict), "invalid_request")
    return value


def validate_manifest(value, policy, approved_baseline):
    require(isinstance(value, dict), "invalid_manifest")
    require(
        set(value) == {"schema", "service", "repository", "commit", "baseline", "images", "run_id"},
        "manifest_fields",
    )
    require(value["schema"] == 1 and value["service"] == policy["service"], "wrong_service")
    require(value["repository"] == policy["repository"], "wrong_repository")
    require(isinstance(value["commit"], str) and SHA.fullmatch(value["commit"]), "invalid_commit")
    require(value["baseline"] == approved_baseline, "baseline_changed")
    require(
        isinstance(value["run_id"], str) and re.fullmatch(r"[1-9][0-9]{0,19}", value["run_id"]),
        "invalid_run",
    )
    images = value["images"]
    require(isinstance(images, dict) and set(images) == set(policy["images"]), "image_set")
    for key, repository in policy["images"].items():
        reference = images[key]
        require(
            isinstance(reference, str)
            and reference.startswith(repository + "@")
            and DIGEST.fullmatch(reference[len(repository) + 1 :]),
            "image_not_allowed",
        )
    # Retrying the same release in another workflow run cannot run migrations again.
    identity = {key: val for key, val in value.items() if key != "run_id"}
    return hashlib.sha256(canonical(identity)).hexdigest()


def github(path, token):
    request = Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "alex-deploy-v1",
        },
    )
    # NAS outbound requests can fail transiently. Retrying read-only verification
    # never bypasses it; authorization errors remain an immediate rejection.
    for attempt in range(3):
        try:
            with urlopen(request, timeout=15) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code in {401, 403}:
                raise Rejected("github_verification_denied") from None
            if error.code != 429 and error.code < 500:
                raise Rejected("github_verification_unavailable") from None
        except (OSError, ValueError):
            pass
        if attempt < 2:
            time.sleep(1 + attempt)
    raise Rejected("github_verification_unavailable")


def verify_source(manifest, policy, token):
    repo = "/repos/" + policy["repository"]
    head = github(repo + "/git/ref/heads/" + policy["branch"], token)
    require(head["object"]["sha"] == manifest["commit"], "candidate_superseded")
    run = github(repo + "/actions/runs/" + manifest["run_id"], token)
    require(
        run["head_sha"] == manifest["commit"]
        and run["path"] == policy["workflow"]
        and run["event"] == "push"
        and run["repository"]["full_name"] == policy["repository"],
        "untrusted_workflow",
    )
    jobs = github(repo + "/actions/runs/" + manifest["run_id"] + "/jobs?per_page=100", token)
    passed = {
        job["name"].split(" / ")[-1]
        for job in jobs["jobs"]
        if job["status"] == "completed" and job["conclusion"] == "success"
    }
    require(set(policy["required_jobs"]) <= passed, "verification_incomplete")


class Engine:
    def __init__(self, root, service):
        require(isinstance(service, str) and NAME.fullmatch(service), "invalid_identity")
        self.root = root
        self.directory = root / "services" / service
        self.policy = json.loads((self.directory / "policy.json").read_text())
        require(self.policy["service"] == service, "policy_identity")
        self.service = service
        self.state = root / "state" / service
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.approved = baseline(self.directory, self.policy["compose_files"])

    @contextlib.contextmanager
    def lock(self, blocking=True):
        with (self.state / "lock").open("a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                raise Rejected("deployment_busy") from None
            yield

    def receipt(self, identity):
        require(isinstance(identity, str) and re.fullmatch(r"[0-9a-f]{64}", identity), "invalid_id")
        path = self.state / "jobs" / identity / "receipt.json"
        require(path.is_file(), "unknown_deployment")
        result = json.loads(path.read_text())
        # Nonterminal state with no live executor is deliberately frozen, never auto-resumed.
        if result["status"] not in TERMINAL and not (self.state / "lock").exists():
            result["status"] = "needs_attention"
        return result

    def latest(self):
        path = self.state / "latest.json"
        return self.receipt(json.loads(path.read_text())["id"]) if path.exists() else None

    def plan(self, manifest):
        identity = validate_manifest(manifest, self.policy, self.approved)
        return {
            "id": identity,
            "service": self.service,
            "commit": manifest["commit"],
            "baseline": self.approved,
            "enabled": self.policy["enabled"],
            "steps": ["pull", "verify_images", "quiesce", "backup", "migrate", "start", "verify"],
            "has_migration": bool(self.policy.get("migration_service")),
        }

    def submit(self, manifest, credentials):
        plan = self.plan(manifest)
        require(self.policy["enabled"], "service_disabled")
        require(
            set(credentials) == {"username", "token"}
            and isinstance(credentials["username"], str)
            and re.fullmatch(r"[A-Za-z0-9-]{1,100}", credentials["username"])
            and isinstance(credentials["token"], str)
            and 1 <= len(credentials["token"]) <= 4096,
            "credentials_invalid",
        )
        identity = plan["id"]
        if (self.state / "jobs" / identity / "receipt.json").is_file():
            return self.receipt(identity)
        with self.lock(blocking=False):
            existing = self.state / "jobs" / identity
            if existing.exists():
                return self.receipt(identity)
            previous = self.latest()
            require(
                not previous or previous["status"] in {"succeeded", "failed_safe"},
                "service_needs_attention",
            )
            verify_source(manifest, self.policy, credentials["token"])
            directory = self.state / "jobs" / identity
            directory.mkdir(mode=0o700, parents=True)
            atomic_json(directory / "manifest.json", manifest)
            receipt = {
                "id": identity,
                "service": self.service,
                "commit": manifest["commit"],
                "status": "queued",
                "phase": "accepted",
                "created_at": int(time.time()),
            }
            atomic_json(directory / "receipt.json", receipt)
            atomic_json(self.state / "latest.json", {"id": identity})
            # Secrets use a pipe, never disk/argv/receipts. Child survives SSH disconnect.
            child = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-I",
                    str(PROGRAM),
                    "worker",
                    self.service,
                    identity,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                env=BASE_ENV,
            )
            try:
                child.stdin.write(canonical(credentials))
                child.stdin.close()
            except (BrokenPipeError, OSError):
                # Keep queued state: explicit administrator reconciliation is required.
                raise Rejected("executor_start_unknown") from None
            return receipt

    def run(self, argv, *, timeout=180, input_data=None, env=None):
        try:
            result = subprocess.run(
                argv,
                input=input_data,
                capture_output=True,
                timeout=timeout,
                env=env or BASE_ENV,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Rejected("command_timeout_or_unavailable") from None
        require(result.returncode == 0, "command_failed")
        return result.stdout

    def compose(self, image_file, *arguments, timeout=240, env=None):
        p = self.policy
        argv = [
            p["docker"],
            "compose",
            "--project-name",
            p["project"],
            "--project-directory",
            p["project_directory"],
        ]
        for name in p["compose_files"]:
            argv += ["-f", str(self.directory / name)]
        argv += ["--env-file", p["runtime_env"], "--env-file", str(image_file)]
        return self.run(argv + list(arguments), timeout=timeout, env=env)

    def registry(self, argv, *, env, input_data=None):
        # Login and digest pulls are safe to repeat before maintenance. Only static
        # classifications leave this process; registry URLs/errors can contain tokens.
        operation = argv[1]
        for attempt in range(3):
            try:
                result = subprocess.run(
                    argv,
                    input=input_data,
                    capture_output=True,
                    timeout=600,
                    env=env,
                    check=False,
                )
                if result.returncode == 0:
                    return
                error = result.stderr.lower()
                if b"unauthorized" in error or b"denied" in error:
                    raise Rejected("registry_access_denied")
                code = "registry_" + operation + "_failed"
            except (OSError, subprocess.TimeoutExpired):
                code = "registry_transport_unavailable"
            if attempt < 2:
                time.sleep(2 + attempt)
        raise Rejected(code)

    def hook(self, name, directory, image_file):
        command = self.policy.get("hooks", {}).get(name)
        if command:
            env = {
                **BASE_ENV,
                "DEPLOY_JOB_DIR": str(directory),
                "DEPLOY_PROJECT_DIR": self.policy["project_directory"],
                "DEPLOY_STARTED_AT": str(int(directory.stat().st_mtime)),
                "DEPLOY_IMAGES_FILE": str(image_file),
            }
            self.run(command, env=env, timeout=300)

    def verify_images(self, manifest):
        for reference in manifest["images"].values():
            info = json.loads(self.run([self.policy["docker"], "image", "inspect", reference]))[0]
            labels = info["Config"].get("Labels") or {}
            require(
                info["Os"] + "/" + info["Architecture"] == self.policy["platform"], "wrong_platform"
            )
            require(
                labels.get("org.opencontainers.image.revision") == manifest["commit"]
                and labels.get("org.opencontainers.image.source")
                == "https://github.com/" + manifest["repository"],
                "wrong_image_source",
            )

    def start(self, images):
        for group in self.policy["start_groups"]:
            self.compose(images, "up", "-d", "--no-deps", "--wait", "--wait-timeout", "180", *group)

    def health(self, images, expected=None):
        for service in self.policy["services"]:
            ids = self.compose(images, "ps", "--all", "--quiet", service).decode().split()
            require(len(ids) == 1, "service_instance_count")
            info = json.loads(self.run([self.policy["docker"], "inspect", ids[0]]))[0]
            require(info["State"]["Running"], "service_not_running")
            health = info["State"].get("Health", {}).get("Status")
            require(health is None or health == "healthy", "service_unhealthy")
            if expected:
                require(
                    info["Config"]["Labels"].get("org.opencontainers.image.revision") == expected,
                    "running_revision_mismatch",
                )
        for check in self.policy.get("http_checks", []):
            try:
                with urlopen(check["url"], timeout=8) as response:
                    status = response.status
            except HTTPError as error:
                status = error.code
            require(status == check["status"], "http_check_failed")

    def execute(self, identity, credentials):
        with self.lock():
            directory = self.state / "jobs" / identity
            manifest = json.loads((directory / "manifest.json").read_text())
            receipt = self.receipt(identity)
            require(receipt["status"] == "queued", "executor_already_started")
            candidate = directory / "images.env"
            previous = directory / "previous-images.env"
            current = Path(self.policy["current_images"])
            quiesced = migrated = False

            def phase(name, status="running", **fields):
                receipt.update(phase=name, status=status, updated_at=int(time.time()), **fields)
                atomic_json(directory / "receipt.json", receipt)

            try:
                phase("pull")
                validate_manifest(manifest, self.policy, self.approved)
                atomic_bytes(
                    candidate,
                    b"".join(
                        (key + "=" + value + "\n").encode()
                        for key, value in sorted(manifest["images"].items())
                    ),
                )
                atomic_bytes(previous, current.read_bytes())
                require(
                    not self.policy.get("migration_service")
                    or self.policy.get("hooks", {}).get("backup"),
                    "migration_requires_backup",
                )
                self.compose(candidate, "config", "--quiet")
                # /run is tmpfs on DSM. Directory removed even when login/pull fails.
                with tempfile.TemporaryDirectory(prefix="alex-deploy-", dir="/run") as config:
                    env = {**BASE_ENV, "DOCKER_CONFIG": config}
                    phase("registry_login")
                    self.registry(
                        [
                            self.policy["docker"],
                            "login",
                            "ghcr.io",
                            "--username",
                            credentials["username"],
                            "--password-stdin",
                        ],
                        input_data=credentials["token"].encode(),
                        env=env,
                    )
                    phase("pull")
                    for reference in set(manifest["images"].values()):
                        self.registry([self.policy["docker"], "pull", reference], env=env)
                self.verify_images(manifest)
                phase("preflight")
                verify_source(manifest, self.policy, credentials["token"])
                credentials.clear()
                self.hook("preflight", directory, candidate)
                # Mark before stopping the first service: partial stops must also recover.
                quiesced = True
                phase("quiesce")
                for service in self.policy["stop_order"]:
                    self.compose(previous, "stop", "--timeout", "90", service, timeout=120)
                phase("backup")
                self.hook("drained", directory, candidate)
                self.hook("backup", directory, candidate)
                if self.policy.get("migration_service"):
                    migrated = True
                    phase("migrate")
                    self.compose(
                        candidate,
                        "run",
                        "--rm",
                        "--no-deps",
                        self.policy["migration_service"],
                        timeout=600,
                    )
                phase("start")
                atomic_bytes(current, candidate.read_bytes())
                self.start(candidate)
                phase("verify")
                self.health(candidate, manifest["commit"])
                self.hook("verify", directory, candidate)
                phase("complete", "succeeded")
            except Exception as error:
                code = str(error) if isinstance(error, Rejected) else "executor_error"
                failed_phase = receipt["phase"]
                if migrated:
                    # New schema may reject the old image; never restore data automatically.
                    phase(failed_phase, "needs_attention", error=code)
                elif quiesced:
                    try:
                        for service in self.policy["stop_order"]:
                            self.compose(candidate, "stop", "--timeout", "90", service, timeout=120)
                        atomic_bytes(current, previous.read_bytes())
                        self.start(previous)
                        self.health(previous)
                        phase(failed_phase, "failed_safe", error=code, previous_restored=True)
                    except Exception:
                        phase(failed_phase, "needs_attention", error=code)
                else:
                    phase(failed_phase, "failed_safe", error=code)
            finally:
                credentials.clear()

    def dispatch(self, request):
        action = request.get("action")
        expected = {
            "inspect": {"action"},
            "plan": {"action", "manifest"},
            "submit": {"action", "manifest", "credentials"},
            "status": {"action", "id"},
        }
        require(action in expected and set(request) == expected[action], "request_fields")
        if action == "inspect":
            return {
                "service": self.service,
                "repository": self.policy["repository"],
                "baseline": self.approved,
                "enabled": self.policy["enabled"],
                "latest": self.latest(),
            }
        if action == "plan":
            return self.plan(request["manifest"])
        if action == "submit":
            return self.submit(request["manifest"], request["credentials"])
        return self.receipt(request["id"])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["entry", "serve", "worker"])
    parser.add_argument("service")
    parser.add_argument("identity", nargs="?")
    args = parser.parse_args()
    try:
        require(NAME.fullmatch(args.service), "invalid_identity")
        if args.mode == "entry":
            require(os.environ.get("SSH_ORIGINAL_COMMAND") == "nas-deploy-v1", "command_denied")
            return subprocess.call(
                [
                    "/usr/bin/sudo",
                    "-n",
                    "/usr/bin/python3",
                    "-I",
                    str(PROGRAM),
                    "serve",
                    args.service,
                ],
                env=BASE_ENV,
            )
        require(os.geteuid() == 0, "root_executor_required")
        for path in [
            ROOT,
            PROGRAM.parent,
            PROGRAM,
            ROOT / "services",
            ROOT / "services" / args.service,
            ROOT / "services" / args.service / "policy.json",
        ]:
            trusted(path)
        engine = Engine(ROOT, args.service)
        for name in engine.policy["compose_files"]:
            trusted(engine.directory / name)
        if args.mode == "serve":
            print(json.dumps(engine.dispatch(read_request())))
        else:
            # Parent writes at most ~4 KiB; do not inherit caller environment or stdin.
            credentials = json.loads(sys.stdin.buffer.read(8192))
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            engine.execute(args.identity, credentials)
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, Rejected) else "request_rejected"
        print(json.dumps({"error": code}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
