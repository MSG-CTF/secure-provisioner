#!/usr/bin/env bash
# Build a static linux/amd64 agent and an importable OCI archive without registry credentials.
set -euo pipefail

if [[ $# != 1 ]]; then
  printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p -- "$1"
output_dir="$(cd -- "$1" && pwd)"
case "$output_dir" in
  "$repo_dir"|"$repo_dir/cmd"|"$repo_dir/internal"|"$repo_dir/scripts")
    printf 'use a dedicated artifact output directory\n' >&2
    exit 2
    ;;
esac
cd -- "$repo_dir"

source_sha="$(git rev-parse HEAD)"
source_epoch="$(git show -s --format=%ct HEAD)"
source_dirty=false
if [[ -n "$(git status --porcelain)" ]]; then source_dirty=true; fi
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local

go mod verify
go build -mod=readonly -trimpath -buildvcs=true -ldflags='-s -w' \
  -o "$output_dir/image-agent-linux-amd64" ./cmd/image-agent
go version -m "$output_dir/image-agent-linux-amd64" > "$output_dir/build-info.txt"

python3 - "$output_dir" "$source_sha" "$source_epoch" "$source_dirty" <<'PY'
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

output, sha, epoch, dirty = sys.argv[1:]
root = pathlib.Path(output)
binary = root / "image-agent-linux-amd64"
metadata = {
    "source_repository": "https://github.com/MSG-CTF/secure-provisioner",
    "source_sha": sha,
    "source_dirty": dirty == "true",
    "source_date_epoch": int(epoch),
    "source_date": datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).isoformat(),
    "platform": "linux/amd64",
    "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
    "docker_buildx_version": subprocess.check_output(["docker", "buildx", "version"], text=True).strip(),
    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    "build_flags": ["CGO_ENABLED=0", "-mod=readonly", "-trimpath", "-buildvcs=true", "-ldflags=-s -w"],
}
(root / "source.json").write_text(json.dumps(metadata, indent=2) + "\n")
PY

cat > "$output_dir/Dockerfile" <<'DOCKERFILE'
FROM scratch
ARG SOURCE_SHA
LABEL org.opencontainers.image.title="Runtime image preparation agent" \
      org.opencontainers.image.source="https://github.com/MSG-CTF/secure-provisioner" \
      org.opencontainers.image.revision="${SOURCE_SHA}"
COPY --chmod=0755 image-agent-linux-amd64 /usr/local/bin/image-agent
ENTRYPOINT ["/usr/local/bin/image-agent"]
CMD ["--idle"]
DOCKERFILE
printf '**\n!Dockerfile\n!image-agent-linux-amd64\n' > "$output_dir/.dockerignore"
docker buildx build --platform linux/amd64 --provenance=false \
  --build-arg "SOURCE_SHA=$source_sha" --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
  --file "$output_dir/Dockerfile" \
  --metadata-file "$output_dir/oci-build-metadata.json" \
  --output "type=oci,dest=$output_dir/image-agent-linux-amd64.oci.tar" "$output_dir"

python3 - "$output_dir" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
with tarfile.open(root / "image-agent-linux-amd64.oci.tar") as archive:
    index = json.load(archive.extractfile("index.json"))
    descriptors = index["manifests"]
    if len(descriptors) != 1:
        raise SystemExit("expected one linux/amd64 OCI image descriptor")
    descriptor = descriptors[0]
    digest = descriptor["digest"]
    algorithm, encoded = digest.split(":", 1)
    manifest_bytes = archive.extractfile(f"blobs/{algorithm}/{encoded}").read()
    if algorithm != "sha256" or hashlib.sha256(manifest_bytes).hexdigest() != encoded:
        raise SystemExit("OCI manifest digest verification failed")
    manifest = json.loads(manifest_bytes)
    for blob in [manifest["config"], *manifest["layers"]]:
        algorithm, encoded = blob["digest"].split(":", 1)
        content = archive.extractfile(f"blobs/{algorithm}/{encoded}").read()
        if algorithm != "sha256" or hashlib.sha256(content).hexdigest() != encoded:
            raise SystemExit("OCI content digest verification failed")
    (root / "oci-image.json").write_text(json.dumps({"platform": "linux/amd64", "manifest_digest": digest, "descriptor": descriptor}, indent=2) + "\n")
files = sorted(path for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS")
(root / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files))
print((root / "oci-image.json").read_text(), end="")
PY
(cd -- "$output_dir" && sha256sum -c SHA256SUMS)
