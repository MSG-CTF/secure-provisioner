#!/usr/bin/env python3
"""Install the fixed deployment helper once through an existing administrator session."""
import argparse
import grp
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile

def install(component, public_key, helper):
    if os.geteuid() != 0 or component not in ("runtime", "scheduler"):
        raise ValueError("Root and a fixed component are required")
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,3}(?: [A-Za-z0-9@._/-]+)?", public_key.strip()):
        raise ValueError("Expected one Ed25519 public key")
    account = "msgctf-deploy"
    try:
        pwd.getpwnam(account)
    except KeyError:
        subprocess.run(["useradd", "--create-home", "--shell", "/bin/sh", account], check=True, capture_output=True)
    home = Path(pwd.getpwnam(account).pw_dir)
    ssh = home / ".ssh"
    ssh.mkdir(mode=0o700, exist_ok=True)
    os.chown(ssh, 0, 0)
    os.chmod(ssh, 0o755)
    command = f"sudo -n /usr/bin/python3 /usr/local/lib/msgctf-deploy/release.py {component}"
    authorized = f'restrict,command="{command}" {public_key.strip()}\n'
    keys = ssh / "authorized_keys"
    keys.write_text(authorized, encoding="utf-8")
    os.chown(keys, 0, 0)
    os.chmod(keys, 0o644)
    target = Path("/usr/local/lib/msgctf-deploy/release.py")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(helper, target)
    os.chown(target, 0, 0)
    os.chmod(target, 0o644)
    sudoers = f"{account} ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/lib/msgctf-deploy/release.py {component}\n"
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temporary:
        temporary.write(sudoers)
        temporary_path = temporary.name
    try:
        subprocess.run(["visudo", "-cf", temporary_path], check=True, capture_output=True)
        target = Path("/etc/sudoers.d/msgctf-ci-deploy")
        shutil.copyfile(temporary_path, target)
        os.chmod(target, 0o440)
    finally:
        Path(temporary_path).unlink(missing_ok=True)
    root = Path("/var/lib/msgctf-deploy")
    root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    print("Fixed deployment entry point installed for " + component)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=("scheduler", "runtime"))
    parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    install(args.component, args.public_key.read_text().strip(), Path(__file__).with_name("release.py"))

if __name__ == "__main__":
    main()
