"""Validate the proposed OpenAPI and published examples; does not test Runtime support.

Development dependencies: PyYAML, jsonschema, openapi-spec-validator.
Run from any directory: python scripts/validate-image-preparation-contract.py
"""

from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate_spec
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "docs" / "api"
EXAMPLES = API / "examples" / "image-preparation"
document = yaml.safe_load((API / "image-preparation.openapi.yaml").read_text(encoding="utf-8"))
validate_spec(document)
base_uri = "https://contract.example.invalid/image-preparation"
registry = Registry().with_resource(
    base_uri, Resource.from_contents(document, default_specification=DRAFT202012)
)


def validator(name):
    return Draft202012Validator(
        {"$ref": f"{base_uri}#/components/schemas/{name}"},
        registry=registry,
        format_checker=FormatChecker(),
    )


def load(name):
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


manifest = load("manifest.json")
for filename, schema_name in manifest.items():
    validator(schema_name).validate(load(filename))


rejected = 0


def reject(name, instance):
    global rejected
    if validator(name).is_valid(instance):
        raise AssertionError(f"{name} unexpectedly accepts invalid contract example: {instance}")
    rejected += 1


query = load("query.json")
invalid = deepcopy(query)
invalid.pop("architecture")
reject("ReadinessQuery", invalid)
invalid = deepcopy(query)
invalid["images"].append(invalid["images"][0])
reject("ReadinessQuery", invalid)
invalid = deepcopy(query)
invalid["images"][0] = "ghcr.io/msg-ctf/challenges/example/web:latest"
reject("ReadinessQuery", invalid)
invalid = deepcopy(query)
invalid["target_ids"].append(invalid["target_ids"][0])
reject("ReadinessQuery", invalid)

target = load("response.json")["targets"][0]
reject("ReadinessTarget", dict(target, ready_node_count=0))
reject("ReadinessTarget", dict(target, observed_at=None))
reject("ReadinessTarget", dict(target, ready=False))
reject("ReadinessTarget", dict(target, ready=False, ready_node_count=0, observed_at=None, valid_until=None))
reject("CreateTracingExtension", {"release_id": None})
reject("CreateTracingExtension", {"architecture": "X86"})
reject("RetryRequest", {"request_id": "retry", "node_uids": []})
reject("PreparationRequest", dict(load("prepare.json"), registry_token="must-not-be-accepted"))

node = load("operation-partial.json")["nodes"][0]
reject("PreparationNode", dict(node, observed_at=None))
invalid = deepcopy(node)
invalid["images"][0]["status"] = "FAILED"
reject("PreparationNode", invalid)
image = node["images"][0]
invalid = deepcopy(image)
invalid.pop("resolved_manifest_digest")
reject("PreparationImage", invalid)
reject("PreparationImage", dict(image, observed_at=None))
operation = load("operation-partial.json")
reject("PreparationOperation", dict(operation, status="SUCCEEDED", nodes=[]))
reject("PreparationOperation", dict(operation, status="SUCCEEDED"))
reject("PreparationOperation", dict(operation, status="PARTIAL", nodes=[node, deepcopy(node)]))
reject("PreparationOperation", dict(operation, status="PARTIAL", nodes=[operation["nodes"][1]]))
reject("PreparationOperation", dict(operation, status="FAILED", nodes=[node]))

# Validate cross-field invariants that JSON Schema cannot express directly.
for filename, name in manifest.items():
    if name != "ReadinessResponse":
        continue
    for row in load(filename)["targets"]:
        assert row["ready_node_count"] <= row["eligible_node_count"]
        assert row["ready"] == (row["ready_node_count"] > 0)
        if row["observed_at"] is not None:
            start = datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(row["valid_until"].replace("Z", "+00:00"))
            assert start < end

canonical = {"schema_version": 1, "architecture": query["architecture"], "images": sorted(query["images"])}
expected_id = "sha256:" + hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()
assert load("response.json")["image_set_id"] == expected_id
assert load("accepted.json")["image_set_id"] == expected_id
assert "unknown-target" not in {t["target_id"] for t in load("response.json")["targets"]}
print(f"OpenAPI valid; {len(manifest)} published examples valid; {rejected} negative cases rejected; invariants valid")
