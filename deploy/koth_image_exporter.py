#!/usr/bin/env python3
"""Export one ticket-approved OCI image on the trusted control server.

Registry credentials stay on this server. Challenge VMs receive OCI bytes only.
"""
import argparse
import base64
import hashlib
import hmac
import http.server
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

IMAGE = re.compile(r"^ghcr\.io/(?P<repository>msg-ctf/challenges/koth-[a-z0-9-]+/[a-z0-9._-]+)@sha256:(?P<digest>[a-f0-9]{64})$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
INDEXES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFESTS = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
MAX_IMAGE_BYTES = 2 * 1024 ** 3
MAX_CACHE_BYTES = 4 * 1024 ** 3


class ExportError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def private_config(path):
    file = Path(path)
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o027 or info.st_uid not in (0, os.getuid()):
        raise ExportError("Private operator configuration required")
    value = json.loads(file.read_text())
    if (set(value) != {"signing_key", "registry_username", "registry_password", "cache_dir"}
            or not all(isinstance(value[k], str) and value[k] for k in value)
            or len(value["signing_key"]) < 32):
        raise ExportError("Invalid operator configuration")
    return value


def verify_ticket(ticket, key, image_ref, now=None):
    now = int(time.time()) if now is None else now
    try:
        if not isinstance(ticket, str) or len(ticket) > 4096 or not IMAGE.fullmatch(image_ref):
            raise ValueError
        encoded, signature = ticket.split(".")
        expected = base64.urlsafe_b64encode(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (set(claims) != {"aud", "challenge_id", "application_id", "version_id", "image_ref", "exp"}
                or claims["aud"] != "msg-koth-image-v1" or claims["image_ref"] != image_ref
                or type(claims["exp"]) is not int or not now < claims["exp"] <= now + 330):
            raise ValueError
        for field in ("challenge_id", "application_id", "version_id"):
            if str(uuid.UUID(claims[field])) != claims[field]:
                raise ValueError
        return claims
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ExportError("Invalid image ticket") from None


class Registry:
    def __init__(self, username, password):
        self.username, self.password, self.token = username, password, None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def response(self, url, authenticated=True):
        for _ in range(4):
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443):
                raise ExportError("Invalid registry transport")
            host = parsed.hostname or ""
            allowed = host == "ghcr.io" or host == "pkg-containers.githubusercontent.com" or host.endswith(".blob.core.windows.net")
            if not allowed:
                raise ExportError("Untrusted registry redirect")
            headers = {"Accept": ", ".join(INDEXES | MANIFESTS) + ", application/octet-stream"}
            if authenticated and host == "ghcr.io":
                headers["Authorization"] = "Bearer " + self.token
            try:
                return self.opener.open(urllib.request.Request(url, headers=headers), timeout=30)
            except urllib.error.HTTPError as error:
                if error.code not in (301, 302, 303, 307, 308) or not error.headers.get("Location"):
                    error.close()
                    raise ExportError("Registry download failed") from None
                url = urllib.parse.urljoin(url, error.headers["Location"])
                error.close()
                # Credentials must never follow a redirect to the blob CDN.
                authenticated = False
        raise ExportError("Too many registry redirects")

    def authenticate(self, repository):
        url = "https://ghcr.io/token?" + urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:" + repository + ":pull"})
        credential = base64.b64encode((self.username + ":" + self.password).encode()).decode()
        request = urllib.request.Request(url, headers={"Authorization": "Basic " + credential})
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(16385)
            if len(raw) > 16384:
                raise ValueError
            data = json.loads(raw)
            token = data.get("token") or data.get("access_token")
            if not isinstance(token, str) or not 16 <= len(token) <= 8192:
                raise ValueError
            self.token = token
        except Exception:
            raise ExportError("Registry authentication failed") from None

    def manifest(self, repository, digest):
        if not DIGEST.fullmatch(digest):
            raise ExportError("Invalid manifest digest")
        with self.response(f"https://ghcr.io/v2/{repository}/manifests/{digest}") as response:
            raw = response.read(1024 * 1024 + 1)
            media = response.headers.get_content_type()
        if len(raw) > 1024 * 1024 or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
            raise ExportError("Manifest digest does not match")
        value = json.loads(raw)
        media = value.get("mediaType", media)
        if media not in INDEXES | MANIFESTS or value.get("schemaVersion") != 2:
            raise ExportError("Unsupported image manifest")
        return raw, value, media

    def blob(self, repository, descriptor, file):
        digest, size = descriptor.get("digest"), descriptor.get("size")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or type(size) is not int or not 0 <= size <= MAX_IMAGE_BYTES:
            raise ExportError("Invalid layer descriptor")
        checksum, length = hashlib.sha256(), 0
        with self.response(f"https://ghcr.io/v2/{repository}/blobs/{digest}") as response, file.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                length += len(chunk)
                if length > size or length > MAX_IMAGE_BYTES:
                    raise ExportError("Layer exceeded declared size")
                checksum.update(chunk); output.write(chunk)
        if length != size or "sha256:" + checksum.hexdigest() != digest:
            raise ExportError("Layer digest does not match")


def add_bytes(archive, name, content):
    info = tarfile.TarInfo(name); info.size = len(content); info.mode = 0o600
    archive.addfile(info, io.BytesIO(content))


def export_image(registry, image_ref, target):
    match = IMAGE.fullmatch(image_ref)
    if match is None:
        raise ExportError("Invalid image reference")
    repository, root_digest = match["repository"], "sha256:" + match["digest"]
    registry.authenticate(repository)
    total, visited = 0, set()
    with tempfile.TemporaryDirectory(prefix="layers-", dir=target.parent) as directory, tarfile.open(target, "w") as archive:
        def manifest(digest):
            nonlocal total
            if digest in visited:
                return None
            visited.add(digest)
            raw, value, media = registry.manifest(repository, digest)
            total += len(raw)
            add_bytes(archive, "blobs/sha256/" + digest.split(":")[1], raw)
            if media in INDEXES:
                children = value.get("manifests")
                if not isinstance(children, list) or not 1 <= len(children) <= 32:
                    raise ExportError("Invalid image index")
                native = [child for child in children if child.get("platform", {}).get("os") == "linux" and child.get("platform", {}).get("architecture") == "amd64"]
                if len(native) != 1:
                    raise ExportError("Exactly one Linux AMD64 image is required")
                manifest(native[0].get("digest", ""))
            else:
                descriptors = [value.get("config"), *value.get("layers", [])]
                if not all(isinstance(d, dict) for d in descriptors) or len(descriptors) > 128:
                    raise ExportError("Invalid image layers")
                for descriptor in descriptors:
                    name = descriptor.get("digest", "")
                    if name in visited:
                        continue
                    if type(descriptor.get("size")) is not int:
                        raise ExportError("Invalid layer size")
                    if descriptor is descriptors[0] and descriptor["size"] > 1024 * 1024:
                        raise ExportError("Image configuration is too large")
                    total += descriptor["size"]
                    if total > MAX_IMAGE_BYTES:
                        raise ExportError("Image exceeds size limit")
                    path = Path(directory) / "blob"
                    registry.blob(repository, descriptor, path)
                    if descriptor is descriptors[0]:
                        config = json.loads(path.read_bytes())
                        if config.get("architecture") != "amd64" or config.get("os") != "linux":
                            raise ExportError("Unexpected image platform")
                    archive.add(path, arcname="blobs/sha256/" + name.split(":")[1], recursive=False)
                    path.unlink(); visited.add(name)
            return {"mediaType": media, "digest": digest, "size": len(raw),
                    "annotations": {"io.containerd.image.name": image_ref, "org.opencontainers.image.ref.name": image_ref}}
        descriptor = manifest(root_digest)
        add_bytes(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add_bytes(archive, "index.json", json.dumps({"schemaVersion": 2, "manifests": [descriptor]}, separators=(",", ":")).encode())


class ImageCache:
    def __init__(self, config):
        self.config = config
        self.root = Path(config["cache_dir"])
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ExportError("Private cache directory required")
        self.lock = threading.Lock()

    def prepare(self, image_ref):
        key = hashlib.sha256(image_ref.encode()).hexdigest()
        target, metadata = self.root / (key + ".oci"), self.root / (key + ".json")
        with self.lock:
            if target.is_file() and not target.is_symlink() and metadata.is_file() and not metadata.is_symlink():
                value = json.loads(metadata.read_text())
                if value.get("image_ref") == image_ref and value.get("size_bytes") == target.stat().st_size:
                    return target, value
            existing = [p for p in self.root.glob("*.oci") if p.is_file() and not p.is_symlink()]
            size = sum(p.stat().st_size for p in existing)
            for old in sorted(existing, key=lambda p: p.stat().st_mtime):
                if size + MAX_IMAGE_BYTES <= MAX_CACHE_BYTES:
                    break
                size -= old.stat().st_size
                old.unlink(); old.with_suffix(".json").unlink(missing_ok=True)
            temporary = self.root / (key + ".pending")
            try:
                export_image(Registry(self.config["registry_username"], self.config["registry_password"]), image_ref, temporary)
                checksum = hashlib.sha256()
                with temporary.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024): checksum.update(chunk)
                value = {"image_ref": image_ref, "sha256": checksum.hexdigest(), "size_bytes": temporary.stat().st_size}
                os.chmod(temporary, 0o600); temporary.replace(target)
                metadata.write_text(json.dumps(value)); os.chmod(metadata, 0o600)
                return target, value
            finally:
                temporary.unlink(missing_ok=True)


def make_handler(config, cache):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/internal/v1/koth_image_exports":
                self.send_error(404); return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 1024:
                    raise ExportError("Invalid request")
                self.connection.settimeout(15)
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict) or set(body) != {"image_ref"}:
                    raise ExportError("Invalid request")
                header = self.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    raise ExportError("Invalid ticket")
                verify_ticket(header[7:], config["signing_key"], body["image_ref"])
            except Exception:
                self.send_error(401, "Invalid image ticket"); return
            try:
                path, value = cache.prepare(body["image_ref"])
                with path.open("rb") as stream:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-tar")
                    self.send_header("Content-Length", str(value["size_bytes"]))
                    self.send_header("X-Content-SHA256", value["sha256"])
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    while chunk := stream.read(1024 * 1024): self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                return
            except Exception as error:
                print(json.dumps({"event": "image_export_failed", "reason": str(error) if isinstance(error, ExportError) else type(error).__name__}), flush=True)
                self.send_error(503, "Image preparation unavailable")

        def log_message(self, *args):
            # Never log request headers, tickets, registry responses or credentials.
            pass
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/msgctf-koth-image-exporter/config.json")
    args = parser.parse_args()
    config = private_config(args.config)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 9402), make_handler(config, ImageCache(config)))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
