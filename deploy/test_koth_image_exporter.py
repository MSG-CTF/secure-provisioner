import base64
import hashlib
import hmac
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch
import uuid

import koth_image_exporter as exporter
import koth_environment_agent as agent

KEY = "test-only-image-export-signing-key-1234567890"


def ticket(image, **extra):
    value = {"aud": "msg-koth-image-v1", "challenge_id": str(uuid.uuid4()), "application_id": str(uuid.uuid4()),
             "version_id": str(uuid.uuid4()), "image_ref": image, "exp": int(time.time()) + 300, **extra}
    encoded = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(KEY.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return encoded + "." + signature


class FakeRegistry:
    def __init__(self):
        config = b'{"architecture":"amd64","os":"linux"}'
        layer = b'author original image layer'
        def descriptor(raw, media):
            return {"mediaType": media, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        self.config, self.layer = descriptor(config, "application/vnd.oci.image.config.v1+json"), descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
        self.value = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": self.config, "layers": [self.layer]}
        self.raw = json.dumps(self.value).encode()
        self.image = "ghcr.io/msg-ctf/challenges/koth-test/service@sha256:" + hashlib.sha256(self.raw).hexdigest()
        self.blobs = {self.config["digest"]: config, self.layer["digest"]: layer}
    def authenticate(self, repository): self.repository = repository
    def manifest(self, repository, digest): return self.raw, self.value, self.value["mediaType"]
    def blob(self, repository, descriptor, file): file.write_bytes(self.blobs[descriptor["digest"]])


class ImageExportTests(unittest.TestCase):
    def setUp(self): self.registry = FakeRegistry()

    def test_exact_approved_image_and_short_expiry_are_required(self):
        image = self.registry.image
        self.assertEqual(exporter.verify_ticket(ticket(image), KEY, image)["image_ref"], image)
        for token in (ticket(image, exp=int(time.time()) - 1), ticket(image, exp=int(time.time()) + 900), ticket(image) + "x"):
            with self.assertRaises(exporter.ExportError): exporter.verify_ticket(token, KEY, image)
        other = image.replace("koth-test", "koth-other")
        with self.assertRaises(exporter.ExportError): exporter.verify_ticket(ticket(image), KEY, other)

    def test_oci_export_preserves_approved_manifest_and_layer_digests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.oci"
            exporter.export_image(self.registry, self.registry.image, path)
            with path.open("rb") as stream: agent.validate_image_archive(stream, self.registry.image)
            with tarfile.open(path) as archive:
                root = json.loads(archive.extractfile("index.json").read())["manifests"][0]
                self.assertEqual(root["digest"], self.registry.image.split("@")[1])
                self.assertEqual(archive.extractfile("blobs/sha256/" + self.registry.image.rsplit(":", 1)[1]).read(), self.registry.raw)

    def test_tar_path_traversal_and_symlinks_are_rejected_before_import(self):
        for name, kind in [("../../outside", tarfile.REGTYPE), ("index.json", tarfile.SYMTYPE)]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as archive:
                item = tarfile.TarInfo(name); item.type = kind; archive.addfile(item)
            data.seek(0)
            with self.assertRaises(ValueError): agent.validate_image_archive(data, self.registry.image)

    def test_corrupted_layer_is_rejected_by_the_node_before_import(self):
        self.registry.blobs[self.registry.layer["digest"]] = b"corrupted"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.oci"
            exporter.export_image(self.registry, self.registry.image, path)
            with path.open("rb") as stream:
                with self.assertRaises(ValueError): agent.validate_image_archive(stream, self.registry.image)

    def test_registry_does_not_forward_authorization_to_blob_redirect(self):
        registry = exporter.Registry("user", "private-registry-password"); registry.token = "private-bearer"
        calls = []
        def open_request(request, **kwargs):
            calls.append(request)
            if len(calls) == 1:
                raise urllib.error.HTTPError(request.full_url, 307, "redirect", {"Location": "https://pkg-containers.githubusercontent.com/blob?signature=example"}, None)
            return io.BytesIO(b"blob")
        with patch.object(registry.opener, "open", side_effect=open_request): registry.response("https://ghcr.io/v2/repo/blobs/sha256:" + "a" * 64)
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer private-bearer")
        self.assertIsNone(calls[1].get_header("Authorization"))

    def test_untrusted_blob_redirect_fails_closed(self):
        registry = exporter.Registry("user", "secret"); registry.token = "bearer"
        error = urllib.error.HTTPError("https://ghcr.io", 307, "redirect", {"Location": "http://169.254.169.254/"}, None)
        with patch.object(registry.opener, "open", side_effect=error):
            with self.assertRaises(exporter.ExportError): registry.response("https://ghcr.io/v2/repo/blobs/sha256:" + "a" * 64)

    def test_registry_layer_digest_mismatch_is_rejected(self):
        registry = exporter.Registry("user", "secret")
        with tempfile.TemporaryDirectory() as directory, patch.object(registry, "response", return_value=io.BytesIO(b"wrong")):
            with self.assertRaises(exporter.ExportError): registry.blob("repo", self.registry.layer, Path(directory) / "blob")

    def test_cached_images_do_not_request_an_export_ticket(self):
        kube = agent.Kubernetes({"namespace": "koth-test"})
        class DenyApi:
            def call(self, *args): raise AssertionError("No ticket should be needed")
        with patch.object(kube, "cached_images", return_value={self.registry.image}):
            kube.ensure_images({"settings": {"containers": [{"image": self.registry.image}]}}, DenyApi(), None)


if __name__ == "__main__": unittest.main()
