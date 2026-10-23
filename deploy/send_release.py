#!/usr/bin/env python3
"""Send a tested artifact and private settings through a pinned SSH connection."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=("scheduler", "runtime"))
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    host = os.environ["DEPLOY_HOST"]
    user = os.environ.get("DEPLOY_USER", "msgctf-deploy")
    port = os.environ.get("DEPLOY_PORT", "22")
    if (
        not re.fullmatch(r"[A-Za-z0-9.-]+", host)
        or not re.fullmatch(r"[a-z_][a-z0-9_-]*", user)
        or not port.isdecimal()
        or not 1 <= int(port) <= 65535
        or not re.fullmatch(r"[0-9a-f]{40}", args.source_sha)
    ):
        raise ValueError("Invalid deployment destination or source")
    values = {
        "artifact": args.artifact.read_bytes(),
        "app.env": os.environ["DEPLOY_ENV"].encode(),
    }
    if args.component == "runtime":
        values["service-token"] = os.environ["DEPLOY_SERVICE_TOKEN"].encode()
    manifest = {
        "component": args.component,
        "source_sha": args.source_sha,
        "checksums": {
            name: hashlib.sha256(value).hexdigest() for name, value in values.items()
        },
    }
    if args.component == "runtime":
        manifest["deployment_strategy"] = "runtime_api_bridge_v1"
    values["release.json"] = json.dumps(manifest).encode()
    with tempfile.TemporaryDirectory(prefix="msgctf-deploy-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        key, hosts, bundle = (
            directory / name for name in ("key", "known_hosts", "release.tar.gz")
        )
        for path, value in (
            (key, os.environ["DEPLOY_SSH_KEY"]),
            (hosts, os.environ["DEPLOY_KNOWN_HOSTS"]),
        ):
            path.write_text(value.rstrip() + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
        with tarfile.open(bundle, "w:gz") as archive:
            for name, value in values.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(value))
        os.chmod(bundle, 0o600)
        command = [
            "ssh",
            "-T",
            "-i",
            str(key),
            "-p",
            port,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + str(hosts),
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=4",
            user + "@" + host,
            "deploy",
        ]
        clean_environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("DEPLOY_")
        }
        with bundle.open("rb") as file:
            completed = subprocess.run(
                command,
                stdin=file,
                env=clean_environment,
                timeout=600,
                capture_output=True,
                text=True,
            )
        safe_lines = [
            line
            for line in completed.stdout.splitlines()
            if line.startswith(("DEPLOYMENT_RESULT=", "ROLLBACK_RESULT="))
        ]
        for line in safe_lines:
            prefix, value = line.split("=", 1)
            report = json.loads(value)
            if (
                prefix == "DEPLOYMENT_RESULT"
                and args.component == "runtime"
                and (
                    report.get("deployment_strategy") != "runtime_api_bridge_v1"
                    or report.get("worker_handoff_verified") is not True
                    or report.get("source_commit") != args.source_sha
                    or report.get("artifact_sha256")
                    != manifest["checksums"]["artifact"]
                    or report.get("component") != "runtime"
                    or report.get("status") != "verified"
                    or report.get("authentication_verified") is not True
                )
            ):
                raise RuntimeError(
                    "Server did not prove the requested runtime handoff protocol"
                )
            print(
                prefix
                + "="
                + json.dumps(
                    {
                        key: report[key]
                        for key in (
                            "component",
                            "source_commit",
                            "artifact_sha256",
                            "status",
                            "authentication_verified",
                            "deployment_strategy",
                            "worker_handoff_verified",
                        )
                        if key in report
                    }
                )
            )
        if completed.returncode or not any(
            line.startswith("DEPLOYMENT_RESULT=") for line in safe_lines
        ):
            raise RuntimeError(
                "Deployment failed; inspect the server through the administrator account"
            )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit("Deployment failed (" + type(error).__name__ + ")") from None
