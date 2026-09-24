"""Explicit administrator-only installer for DSM; run with root after reviewing a policy.

Creates one dedicated account, a fixed sudo command and a restricted SSH public key.
Reinstallation replaces only this service's registered policy/key and shared agent code.
Does not restart applications, enable a service policy, or execute a deployment.
"""

import argparse
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path("/volume4/docker/alex-deploy")
PROGRAM = Path("/usr/local/libexec/alex-deploy/agent.py")


def write_passwd(path, rows):
    original = path.stat()
    fd, temporary = tempfile.mkstemp(prefix=".alex-passwd-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write("\n".join(rows) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), original.st_mode & 0o777)
            os.fchown(stream.fileno(), original.st_uid, original.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore_existing_shells(before, after):
    # synouser can reset custom shells of unrelated users to nologin when rebuilding passwd.
    existing = {row.split(":")[0]: row.split(":") for row in before}
    output = []
    for row in after:
        fields = row.split(":")
        old = existing.get(fields[0])
        if old and old[2] == fields[2]:
            fields[6] = old[6]
        output.append(":".join(fields))
    return output


def create_account(user, service, passwd=Path("/etc/passwd")):
    before = passwd.read_text().splitlines()
    backups = ROOT / "admin-backups"
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backups / ("passwd-before-" + user)
    if not backup.exists():
        backup.write_text("\n".join(before) + "\n")
        backup.chmod(0o600)
    try:
        result = subprocess.run(
            [
                "/usr/syno/sbin/synouser",
                "--add",
                user,
                secrets.token_urlsafe(48),
                "NAS deployment: " + service,
                "0",
                "",
                "0",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("DSM account creation failed")
    finally:
        after = passwd.read_text().splitlines()
        restored = restore_existing_shells(before, after)
        if restored != after:
            write_passwd(passwd, restored)


def install(source, service_directory, public_key, source_ip):
    if os.geteuid() != 0:
        raise ValueError("Installer requires the existing administrator connection")
    os.umask(0o077)
    policy = json.loads((service_directory / "policy.json").read_text())
    service = policy["service"]
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,24}", service):
        raise ValueError("Invalid service name")
    # Account is distinct from the namespace: deploy-fixture -> deploy-fixture, ass -> deploy-ass.
    user = service if service.startswith("deploy-") else "deploy-" + service
    address = str(ipaddress.IPv4Address(source_ip))
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?", public_key.strip()):
        raise ValueError("Expected a single ed25519 public key")
    for name in policy["compose_files"]:
        if Path(name).name != name or not (service_directory / name).is_file():
            raise ValueError("Compose files must be reviewed flat files in the service directory")
    marker = ROOT / "accounts" / user
    try:
        account = pwd.getpwnam(user)
        if not marker.is_file():
            raise ValueError("Existing account is not managed by this installer")
    except KeyError:
        create_account(user, service)
        account = pwd.getpwnam(user)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    ROOT.chmod(0o700)
    for name in ["services", "accounts", "state"]:
        (ROOT / name).mkdir(mode=0o700, exist_ok=True)
    marker.write_text(service + "\n")
    destination = ROOT / "services" / service
    destination.mkdir(mode=0o700, exist_ok=True)
    for path in service_directory.iterdir():
        if path.is_file() and path.suffix in {".json", ".yaml", ".py"}:
            shutil.copyfile(path, destination / path.name)
            (destination / path.name).chmod(0o600)
    # Shared-folder ACLs can deny traversal regardless of child mode bits. Keep the
    # public entry outside DSM shares; only its root subprocess accesses service data.
    PROGRAM.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    PROGRAM.parent.chmod(0o755)
    shutil.copyfile(source / "agent.py", PROGRAM)
    PROGRAM.chmod(0o644)
    if (ROOT / "agent.py").exists():
        (ROOT / "agent.py").unlink()
    # DSM ordinary accounts may have /sbin/nologin. Only change this dedicated account.
    passwd = Path("/etc/passwd")
    rows = passwd.read_text().splitlines()
    updated = []
    for row in rows:
        fields = row.split(":")
        if fields[0] == user:
            fields[6] = "/bin/sh"
        updated.append(":".join(fields))
    if updated != rows:
        write_passwd(passwd, updated)
    home = Path(account.pw_dir)
    home.mkdir(mode=0o755, parents=True, exist_ok=True)
    # Deployment account cannot replace its own key, shell rc, or authorized command.
    os.chown(home, 0, 0)
    home.chmod(0o755)
    ssh = home / ".ssh"
    ssh.mkdir(mode=0o755, exist_ok=True)
    os.chown(ssh, 0, 0)
    ssh.chmod(0o755)
    auth = ssh / "authorized_keys"
    auth.write_text(
        'restrict,from="'
        + address
        + '",command="/usr/bin/python3 -I '
        + str(PROGRAM)
        + " entry "
        + service
        + '" '
        + public_key.strip()
        + "\n"
    )
    os.chown(auth, 0, 0)
    auth.chmod(0o644)
    sudo = Path("/etc/sudoers.d") / ("alex-" + user)
    sudo.write_text(
        user
        + " ALL=(root) NOPASSWD: /usr/bin/python3 -I "
        + str(PROGRAM)
        + " serve "
        + service
        + "\n"
    )
    sudo.chmod(0o440)
    try:
        # DSM does not ship visudo; sudo parses the complete configuration for this user.
        subprocess.run(
            ["/usr/bin/sudo", "-n", "-l", "-U", user],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        sudo.unlink()
        raise
    # Remove inherited Synology ACLs only from the newly managed files/directories.
    for path in [ROOT, *(ROOT.rglob("*")), PROGRAM.parent, PROGRAM, home, ssh, auth, sudo]:
        if not path.is_symlink():
            subprocess.run(
                ["/usr/syno/bin/synoacltool", "-del", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    print(
        json.dumps(
            {
                "service": service,
                "user": user,
                "enabled": policy["enabled"],
                "installed": True,
                "application_restarted": False,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-directory", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--source-ip", required=True)
    args = parser.parse_args()
    install(
        Path(__file__).resolve().parent,
        args.service_directory,
        args.public_key.read_text(),
        args.source_ip,
    )
