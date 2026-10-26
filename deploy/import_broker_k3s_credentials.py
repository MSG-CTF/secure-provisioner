#!/usr/bin/env python3
"""Import a Broker credential using its verified Scheduler lifecycle identity."""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

try:
    import fcntl
except ImportError:  # Importable for tooling; the deployment command is Linux-only.
    fcntl = None


class ImportFailure(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def json_value(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ImportFailure("Duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, TypeError, UnicodeError):
        raise ImportFailure("Invalid JSON input") from None


def uuid_value(value):
    try:
        if not isinstance(value, str) or value != value.strip():
            raise ValueError()
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ImportFailure("Missing or invalid target identity; wait for a current Broker node observation") from None


def https_endpoint(value):
    try:
        url = urllib.parse.urlsplit(value)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.query or url.fragment):
            raise ValueError()
        url.port
        return url
    except (ValueError, TypeError, AttributeError):
        raise ImportFailure("A verified HTTPS endpoint is required") from None


def fetch_credential(base_url, resource_id, token):
    resource_id = uuid_value(resource_id)
    https_endpoint(base_url)
    if not isinstance(token, str) or len(token) < 32 or any(c.isspace() for c in token):
        raise ImportFailure("Broker Runtime token is missing or invalid")
    url = base_url.rstrip("/") + "/v1/runtime/k3s-credentials/" + resource_id
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 1024 * 1024:
                raise ImportFailure("Broker credential response was rejected")
    except (urllib.error.URLError, OSError):
        raise ImportFailure("Broker credential request failed; response details suppressed") from None
    return json_value(raw)


def run_command(args, *, input=None):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ImportFailure("Credential or Kubernetes verification failed; command details suppressed")
    return result.stdout.strip()


def checked_run(runner, args, input):
    try:
        return runner(args, input=input)
    except (OSError, subprocess.SubprocessError, ImportFailure):
        raise ImportFailure("Credential or Kubernetes verification failed; command details suppressed") from None


def decoded(value):
    try:
        if not isinstance(value, str) or not value:
            raise ValueError()
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error):
        raise ImportFailure("Invalid embedded credential data") from None


def verify_credential(credential, resource_id, runner, kubectl_command):
    if not isinstance(credential, dict) or credential.get("schema_version") != 1:
        raise ImportFailure("Unsupported Broker credential response")
    if uuid_value(credential.get("resource_target_id")) != resource_id:
        raise ImportFailure("Broker credential belongs to a different resource")
    target_id = uuid_value(credential.get("target_id"))
    server = credential.get("server_url")
    server_url = https_endpoint(server)
    if server_url.port != 6443 or server_url.path not in ("", "/"):
        raise ImportFailure("Unexpected Kubernetes API endpoint")
    raw = decoded(credential.get("kubeconfig_base64"))
    config = json_value(checked_run(runner, [*kubectl_command, "--kubeconfig=/dev/stdin", "config", "view", "--raw", "-o", "json"], raw))
    try:
        if any(len(config.get(key, [])) != 1 for key in ("clusters", "users", "contexts")):
            raise ValueError()
        cluster = config["clusters"][0]["cluster"]
        user = config["users"][0]["user"]
        context = config["contexts"][0]
        if (set(cluster) != {"server", "certificate-authority-data"}
                or cluster["server"] != server
                or set(user) != {"client-certificate-data", "client-key-data"}
                or config.get("current-context") != context["name"]
                or context["context"].get("cluster") != config["clusters"][0]["name"]
                or context["context"].get("user") != config["users"][0]["name"]):
            raise ValueError()
        decoded(cluster["certificate-authority-data"])
        decoded(user["client-key-data"])
        certificate = decoded(user["client-certificate-data"])
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
        if fingerprint != credential.get("client_certificate_fingerprint_sha256"):
            raise ValueError()
        enddate = checked_run(runner, ["openssl", "x509", "-noout", "-enddate", "-checkend", "300"], certificate)
        actual_expiry = ssl.cert_time_to_seconds(enddate.splitlines()[0].removeprefix("notAfter="))
        advertised = datetime.datetime.fromisoformat(credential["client_certificate_not_after"].replace("Z", "+00:00"))
        if advertised.tzinfo is None or advertised.timestamp() != actual_expiry:
            raise ValueError()
    except (KeyError, IndexError, ValueError, TypeError, AttributeError):
        raise ImportFailure("Kubeconfig security settings or certificate metadata do not match Broker") from None
    nodes = json_value(checked_run(runner, [*kubectl_command, "--kubeconfig=/dev/stdin", "--request-timeout=10s", "get", "nodes", "-o", "json"], raw))
    try:
        items = nodes["items"]
        if len(items) != 1 or items[0]["metadata"]["uid"] != target_id:
            raise ValueError()
        node = items[0]
        if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in node["status"].get("conditions", [])):
            raise ValueError()
        return target_id, raw, node["status"]["nodeInfo"]["architecture"]
    except (KeyError, IndexError, ValueError, TypeError):
        raise ImportFailure("Expected one Ready Kubernetes node with the advertised target_id") from None


def no_symlinks(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ImportFailure("Symlink paths are not supported for registry or credential storage")


def write_atomic(path, data, owner, mode, *, immutable=False):
    no_symlinks(path)
    if immutable and path.exists():
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or path.read_bytes() != data
                or stat.S_IMODE(info.st_mode) != mode or (info.st_uid, info.st_gid) != owner):
            raise ImportFailure("Existing credential file differs or has unsafe permissions")
        return
    fd, temporary = tempfile.mkstemp(prefix=".credential-import-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, *owner)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if immutable:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def import_credential(credential, resource_id, registry_path, template, credential_directory,
                      *, output_registry, validator_binary, runner=run_command, kubectl_command=("kubectl",)):
    if fcntl is None:
        raise ImportFailure("Credential import must run on Linux")
    resource_id = uuid_value(resource_id)
    registry_path = Path(registry_path).absolute()
    output_registry = Path(output_registry).absolute()
    credential_directory = Path(credential_directory).absolute()
    no_symlinks(registry_path)
    no_symlinks(output_registry)
    no_symlinks(credential_directory)
    if output_registry == registry_path or (output_registry.exists() and os.path.samefile(output_registry, registry_path)):
        raise ImportFailure("Output must be a separate registry candidate, never the live registry")
    if not registry_path.is_file():
        raise ImportFailure("An existing Runtime registry is required")
    lock_path = registry_path.with_name(registry_path.name + ".import.lock")
    no_symlinks(lock_path)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ImportFailure("Another credential import is running") from None
        original = registry_path.read_bytes()
        registry = json_value(original)
        if not isinstance(registry, dict) or set(registry) != {"clusters"} or not isinstance(registry["clusters"], list):
            raise ImportFailure("Invalid Runtime registry")
        target_id, kubeconfig, architecture = verify_credential(credential, resource_id, runner, kubectl_command)
        seen = set()
        existing = None
        for entry in registry["clusters"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("target_id"), str) or entry["target_id"] in seen:
                raise ImportFailure("Duplicate or invalid registry target")
            seen.add(entry["target_id"])
            broker_id = entry.get("broker_resource_target_id")
            if ((entry["target_id"] == resource_id and target_id != resource_id)
                    or (broker_id == resource_id and entry["target_id"] != target_id)):
                raise ImportFailure("Legacy or changed target identity requires operator migration; existing cleanup routes were preserved")
            if entry["target_id"] == target_id:
                if broker_id not in (None, resource_id):
                    raise ImportFailure("Node identity is already assigned to a different Broker resource")
                existing = entry
        if existing is None:
            required = {"provider", "region", "architecture", "public_gateway", "enabled"}
            if not isinstance(template, dict) or not required <= set(template) or type(template["enabled"]) is not bool:
                raise ImportFailure("An explicit cluster policy template is required")
            existing = json_value(json.dumps(template))
            registry["clusters"].append(existing)
        if existing.get("architecture", "").lower() != architecture:
            raise ImportFailure("Cluster policy architecture differs from the observed node")
        if registry_path.read_bytes() != original:
            raise ImportFailure("Registry changed during verification; retry without overwriting it")
        info = registry_path.stat()
        owner = (info.st_uid, info.st_gid)
        # Use Runtime's real parser instead of duplicating its security/policy
        # rules. The temporary credential never becomes a live registry input.
        with tempfile.TemporaryDirectory(prefix=".credential-validation-", dir=registry_path.parent) as staging:
            staged_credential = Path(staging) / "kubeconfig"
            staged_credential.write_text(kubeconfig)
            staged_credential.chmod(0o600)
            existing.update(target_id=target_id, broker_resource_target_id=resource_id, kubeconfig_path=str(staged_credential))
            staged_registry = Path(staging) / "registry.json"
            staged_registry.write_text(json.dumps(registry))
            receipt = json_value(checked_run(runner, [str(validator_binary), "--validate-registry", str(staged_registry)], None))
            if receipt != {"registry_valid": True}:
                raise ImportFailure("Runtime did not validate the proposed registry")
        if registry_path.read_bytes() != original:
            raise ImportFailure("Registry changed during validation; retry from its current contents")
        if not credential_directory.exists():
            credential_directory.mkdir(mode=0o750)
            os.chown(credential_directory, *owner)
        directory_info = credential_directory.stat()
        if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_mode & 0o022:
            raise ImportFailure("Credential directory must not be writable by group or other users")
        digest = hashlib.sha256(kubeconfig.encode()).hexdigest()
        destination = credential_directory / (resource_id + "-" + digest[:16] + ".yaml")
        write_atomic(destination, kubeconfig.encode(), owner, 0o640, immutable=True)
        existing.update(target_id=target_id, broker_resource_target_id=resource_id, kubeconfig_path=str(destination))
        updated = (json.dumps(registry, indent=2) + "\n").encode()
        if registry_path.read_bytes() != original:
            raise ImportFailure("Registry changed before commit; existing registry was preserved")
        # A non-cooperating writer can change the live registry at any time.
        # Never replace it here: prepare an immutable candidate for activation.
        write_atomic(output_registry, updated, owner, stat.S_IMODE(info.st_mode), immutable=True)
        return {"resource_target_id": resource_id, "target_id": target_id,
                "registry_path": str(output_registry), "source_registry_path": str(registry_path),
                "source_registry_sha256": hashlib.sha256(original).hexdigest(),
                "kubeconfig_path": str(destination), "prepared": True, "requires_activation": True}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker-base-url", default="https://broker.mjsec.kr/api")
    parser.add_argument("--resource-target-id", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--output-registry", type=Path, required=True)
    parser.add_argument("--runtime-binary", type=Path, default=Path("/opt/secure-provisioner/secure-provisioner"))
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--credential-directory", type=Path, required=True)
    parser.add_argument("--k3s", action="store_true", help="Use k3s kubectl instead of kubectl")
    args = parser.parse_args()
    try:
        credential = fetch_credential(args.broker_base_url, args.resource_target_id, args.token_file.read_text().strip())
        result = import_credential(credential, args.resource_target_id, args.registry,
                                   json_value(args.template.read_bytes()), args.credential_directory,
                                   output_registry=args.output_registry, validator_binary=args.runtime_binary,
                                   kubectl_command=("k3s", "kubectl") if args.k3s else ("kubectl",))
        print(json.dumps(result))
        return 0
    except ImportFailure as error:
        print(str(error), file=sys.stderr)
    except (OSError, ValueError):
        print("Credential import failed; sensitive input and command details suppressed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
