import copy
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

import koth_environment_agent as agent


def identifier():
    return str(uuid.uuid4())


def fixture():
    challenge = identifier()
    token = "test_only_environment_agent_credential_1234567890"
    protected = "test_only_game_token_not_an_agent_token"
    image = "ghcr.io/msg-ctf/challenges/koth-demo/service@sha256:" + "a" * 64
    game = {"challenge_id": challenge, "namespace": "koth-demo", "deployment": "game", "source_revision": "b" * 40,
            "token": token, "containers": {"service": {"image": image, "managed_secrets": ["runtime-env"],
            "protected": {"INTERNAL_TOKEN": hmac.new(token.encode(), protected.encode(), hashlib.sha256).hexdigest()}}}}
    config = {"schema_version": 1, "target_id": "gcp:123", "base_url": "https://platform.example/internal/v1/koth_environments", "games": [game]}
    desired = {"challenge_id": challenge, "target_id": "gcp:123", "source_revision": "b" * 40,
               "application_id": identifier(), "version_id": identifier(), "can_apply": True, "changed": True,
               "settings": {"containers": [{"name": "service", "image": image, "entries": {
                   "PORT": {"value": "8080", "required": True, "locked": False, "kind": "env", "operator_override": False},
                   "INTERNAL_TOKEN": {"value": protected, "required": True, "locked": True, "kind": "secret", "operator_override": True},
                   "OPTION": {"value": None, "required": False, "locked": False, "kind": "secret", "operator_override": False},
               }}]}}
    return config, game, desired


class MemoryJournal:
    def __init__(self): self.state = {}
    def read(self): return copy.deepcopy(self.state)
    def write(self, state): self.state = copy.deepcopy(state)


class FakeBackend:
    def __init__(self, desired):
        self.desired = copy.deepcopy(desired)
        self.events = []
        self.drop_ack = False
        self.supersede_on_check = False
        self.gets = 0

    def get(self, known=None):
        self.gets += 1
        result = copy.deepcopy(self.desired)
        if self.supersede_on_check and self.gets > 1:
            result["application_id"] = identifier()
        if known == result["application_id"]:
            result["changed"], result["settings"] = False, None
        return result

    def status(self, desired, state, error_code=None):
        self.events.append((desired["application_id"], state, error_code))
        if self.drop_ack and state == "APPLIED":
            self.drop_ack = False
            raise agent.NetworkUnavailable()
        return {"state": "READY" if state == "APPLIED" else state}


class FakeKubernetes:
    def __init__(self, game, initial):
        self.game = game
        self.original = {"metadata": {"labels": {"app": "game"}}, "spec": {
            "runtimeClassName": "gvisor", "automountServiceAccountToken": False,
            "containers": [{"name": "service", "image": game["containers"]["service"]["image"],
                "envFrom": [{"secretRef": {"name": "runtime-env"}}], "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                "resources": {"limits": {"cpu": "1", "memory": "256Mi"}}, "securityContext": {"readOnlyRootFilesystem": True}}],
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "state"}}]}}
        self.current = copy.deepcopy(self.original)
        self.initial = copy.deepcopy(initial)
        self.secrets = {}
        self.patches = []
        self.fail_ready = False
        self.external_change = False
        self.crash_after_patch = False

    def deployment(self): return {"spec": {"template": copy.deepcopy(self.current)}}
    def collect_unused_secrets(self): pass
    def ensure_images(self, desired, api, export_url): pass
    secret_name = agent.Kubernetes.secret_name
    template = agent.Kubernetes.template

    def ensure_secrets(self, desired):
        self.secrets[desired["application_id"]] = copy.deepcopy(desired["settings"])

    def values_match(self, desired):
        current = self.current.get("metadata", {}).get("annotations", {}).get(agent.APPLICATION)
        actual = self.secrets.get(current, self.initial)
        return actual == desired["settings"]

    def patch(self, before, after):
        if self.current != before:
            raise agent.Fault("ROLLBACK_CONFLICT")
        self.current = copy.deepcopy(after)
        self.patches.append((copy.deepcopy(before), copy.deepcopy(after)))
        if self.crash_after_patch:
            self.crash_after_patch = False
            raise SystemExit("simulated process crash")

    def ready(self):
        if self.fail_ready:
            self.fail_ready = False
            if self.external_change:
                self.current["metadata"]["labels"]["operator-change"] = "keep"
            raise agent.Fault("VM_UNAVAILABLE")


class EnvironmentAgentTests(unittest.TestCase):
    def setUp(self):
        self.config, self.game, self.desired = fixture()
        self.journal = MemoryJournal()
        self.api = FakeBackend(self.desired)
        baseline = copy.deepcopy(self.desired["settings"])
        baseline["containers"][0]["entries"]["PORT"]["value"] = "8081"
        self.kube = FakeKubernetes(self.game, baseline)
        self.worker = agent.Agent(self.config, self.game, self.journal, self.api, self.kube)

    def test_validate_fixed_scope_and_protected_auth(self):
        agent.validate_config(self.config)
        agent.validate_desired(self.config, self.game, self.desired)
        for field, value, code in [("target_id", "gcp:456", "VM_UNAVAILABLE"),
                                  ("challenge_id", identifier(), "VM_UNAVAILABLE"),
                                  ("source_revision", "c" * 40, "SOURCE_CHANGED")]:
            altered = copy.deepcopy(self.desired); altered[field] = value
            with self.assertRaisesRegex(agent.Fault, code):
                agent.validate_desired(self.config, self.game, altered)
        altered = copy.deepcopy(self.desired)
        altered["settings"]["containers"][0]["entries"]["INTERNAL_TOKEN"]["value"] = "changed"
        with self.assertRaisesRegex(agent.Fault, "ENVIRONMENT_MISMATCH"):
            agent.validate_desired(self.config, self.game, altered)

    def test_https_no_redirect_or_proxy_credentials(self):
        for url in ["http://example/internal/v1/koth_environments", "https://a:b@example/internal/v1/koth_environments",
                    "https://example/other", "https://example/internal/v1/koth_environments?q=1"]:
            config = copy.deepcopy(self.config); config["base_url"] = url
            with self.assertRaises(ValueError): agent.validate_config(config)
        self.assertIsNone(agent.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_scope_cannot_add_or_replace_an_image(self):
        for transform in [lambda item: item.update(image="unapproved:latest"), lambda item: item.update(name="sidecar")]:
            desired = copy.deepcopy(self.desired)
            transform(desired["settings"]["containers"][0])
            with self.assertRaisesRegex(agent.Fault, "IMAGE_MISMATCH"):
                agent.validate_desired(self.config, self.game, desired)

    def test_baseline_adopted_without_restart(self):
        self.kube.initial = copy.deepcopy(self.desired["settings"])
        self.assertEqual(self.worker.tick(), "complete")
        self.assertEqual(self.kube.patches, [])
        self.assertEqual(self.kube.secrets, {})
        self.assertEqual([e[1] for e in self.api.events], ["APPLIED"])
        self.assertEqual(self.worker.tick(), "unchanged")

    def test_changes_only_environment_and_persists_ack(self):
        self.assertEqual(self.worker.tick(), "complete")
        self.assertEqual(len(self.kube.patches), 1)
        self.assertEqual([e[1] for e in self.api.events], ["APPLYING", "APPLIED"])
        before, after = self.kube.patches[0]
        original = copy.deepcopy(before["spec"])
        changed = copy.deepcopy(after["spec"])
        original["containers"][0].pop("envFrom")
        changed["containers"][0].pop("envFrom")
        self.assertEqual(original, changed)
        self.assertEqual(self.worker.tick(), "unchanged")
        self.assertEqual(len(self.kube.patches), 1)

    def test_lost_ack_and_agent_restart_never_repeat_rollout(self):
        self.api.drop_ack = True
        with self.assertRaises(agent.NetworkUnavailable): self.worker.tick()
        self.assertEqual(self.journal.state["phase"], "healthy")
        restarted = agent.Agent(self.config, self.game, self.journal, self.api, self.kube)
        self.assertEqual(restarted.tick(), "complete")
        self.assertEqual(len(self.kube.patches), 1)
        self.assertEqual(len([e for e in self.api.events if e[1] == "APPLIED"]), 2)

    def test_crash_after_committed_patch_recovers_without_duplicate(self):
        self.kube.crash_after_patch = True
        with self.assertRaises(SystemExit): self.worker.tick()
        self.assertEqual(self.journal.state["phase"], "prepared")
        restarted = agent.Agent(self.config, self.game, self.journal, self.api, self.kube)
        self.assertEqual(restarted.tick(), "complete")
        self.assertEqual(len(self.kube.patches), 1)

    def test_failed_rollout_rolls_back_and_does_not_loop(self):
        self.kube.fail_ready = True
        self.assertEqual(self.worker.tick(), "rejected")
        self.assertEqual(self.kube.current, self.kube.original)
        self.assertEqual(len(self.kube.patches), 2)
        self.assertEqual(self.api.events[-1][1:], ("FAILED", "ROLLOUT_FAILED"))
        self.assertEqual(self.worker.tick(), "unchanged")
        self.assertEqual(len(self.kube.patches), 2)

    def test_concurrent_operator_change_is_not_overwritten(self):
        self.kube.fail_ready, self.kube.external_change = True, True
        self.assertEqual(self.worker.tick(), "rejected")
        self.assertEqual(self.api.events[-1][1:], ("FAILED", "ROLLBACK_CONFLICT"))
        self.assertEqual(self.kube.current["metadata"]["labels"]["operator-change"], "keep")
        self.assertEqual(len(self.kube.patches), 1)

    def test_game_active_and_superseded_jobs_do_not_patch(self):
        self.api.desired["can_apply"] = False
        self.assertEqual(self.worker.tick(), "rejected")
        self.assertEqual(self.api.events[-1][2], "GAME_ACTIVE")
        self.assertEqual(self.kube.patches, [])
        self.api.desired["can_apply"] = True
        self.api.desired["application_id"] = identifier()
        self.api.gets, self.api.supersede_on_check = 0, True
        with self.assertRaises(agent.Superseded): self.worker.tick()
        self.assertEqual(self.kube.patches, [])

    def test_new_job_after_failed_apply_and_old_job_cannot_overwrite(self):
        self.kube.fail_ready = True
        self.worker.tick()
        self.api.desired["application_id"] = identifier()
        self.assertEqual(self.worker.tick(), "complete")
        self.assertEqual(len(self.kube.patches), 3)
        previous_id = self.journal.state["application_id"]
        self.api.desired["application_id"] = identifier()
        self.api.desired["version_id"] = identifier()
        self.api.desired["settings"]["containers"][0]["entries"]["PORT"]["value"] = "8090"
        self.assertEqual(self.worker.tick(), "complete")
        self.assertNotEqual(previous_id, self.journal.state["application_id"])
        self.assertEqual(len(self.kube.patches), 4)

    def test_no_false_ack_when_healthy_workload_drifted(self):
        self.api.drop_ack = True
        with self.assertRaises(agent.NetworkUnavailable): self.worker.tick()
        self.kube.secrets.clear()
        self.assertEqual(self.worker.tick(), "rejected")
        self.assertEqual(self.api.events[-1][2], "ENVIRONMENT_MISMATCH")
        self.assertEqual(len(self.kube.patches), 1)

    def test_literal_and_empty_values_are_preserved_unset_is_omitted(self):
        kube = agent.Kubernetes(self.game)
        desired = copy.deepcopy(self.desired)
        desired["settings"]["containers"][0]["entries"]["PORT"]["value"] = '$(NAME) # "quoted"'
        desired["settings"]["containers"][0]["entries"]["EMPTY"] = {"value": "", "required": False}
        calls = []
        kube.run = lambda args, body=None, **kw: calls.append((args, body))
        kube.ensure_secrets(desired)
        secret = calls[-1][1]
        self.assertNotIn("OPTION", secret["data"])
        self.assertEqual(secret["data"]["EMPTY"], "")
        self.assertEqual(secret["data"]["PORT"], "JChOQU1FKSAjICJxdW90ZWQi")
        self.assertTrue(secret["immutable"])

    def test_conflicting_secret_is_not_replaced(self):
        kube = agent.Kubernetes(self.game)
        kube.run = lambda *args, **kwargs: {"data": {"PORT": "wrong"}, "metadata": {"labels": {}}, "immutable": True}
        with self.assertRaisesRegex(agent.Fault, "SECRET_CONFLICT"):
            kube.ensure_secrets(self.desired)

    def test_removed_managed_variables_cannot_be_adopted_as_a_matching_subset(self):
        kube = agent.Kubernetes(self.game)
        deployment = copy.deepcopy(self.kube.deployment())
        deployment['metadata'] = {'generation':1}
        deployment['status'] = {'observedGeneration':1,'updatedReplicas':1,'readyReplicas':1}
        deployment['spec']['selector'] = {'matchLabels':{'app':'game'}}
        kube.deployment = lambda: deployment
        values = {k:e['value'] for k,e in self.desired['settings']['containers'][0]['entries'].items() if e['value'] is not None}
        values['REMOVED_SETTING'] = 'stale'
        def run(args, **kwargs):
            if args[0:2] == ['get','pods']:
                return {'items':[{'metadata':{'name':'pod'},'status':{'conditions':[{'type':'Ready','status':'True'}]}}]}
            if args[0:2] == ['get','secret']:
                return {'data':{k:base64.b64encode(v.encode()).decode() for k,v in values.items()}}
            if args[0] == 'exec':
                return ('\0'.join(k+'='+v for k,v in values.items())+'\0PATH=/usr/bin\0OPTION=image-default\0').encode()
            raise AssertionError('Unexpected Kubernetes operation')
        kube.run = run
        self.assertFalse(kube.values_match(self.desired))
        del values['REMOVED_SETTING']
        self.assertTrue(kube.values_match(self.desired))
        deployment['spec']['template']['spec']['containers'][0]['env'] = [{'name':'OPTION','value':'stale-platform-value'}]
        self.assertFalse(kube.values_match(self.desired))

    def test_unrelated_env_sources_and_template_changes_are_rejected(self):
        original = copy.deepcopy(self.kube.original)
        original["spec"]["containers"][0]["envFrom"].append({"configMapRef": {"name": "other"}})
        with self.assertRaisesRegex(agent.Fault, "ENVIRONMENT_MISMATCH"):
            self.kube.template(original, self.desired)

    def test_cleanup_keeps_pod_and_rollback_references_and_uses_uid_preconditions(self):
        kube = agent.Kubernetes(self.game)
        suffix = "-" + "a" * 8
        names = {k:"koth-env-" + str(i) * 32 + suffix for i,k in enumerate(["current","rollback","pod","unused"],1)}
        deployment = copy.deepcopy(self.kube.deployment())
        deployment["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [{"secretRef":{"name":names["current"]}}]
        kube.deployment = lambda: deployment
        calls = []
        def run(args, body=None):
            if args[0:2] == ["get","replicasets"]:
                return {"items":[{"spec":{"template":{"spec":{"containers":[{"envFrom":[{"secretRef":{"name":names["rollback"]}}]}]}}}}]}
            if args[0:2] == ["get","pods"]:
                return {"items":[{"spec":{"containers":[],"volumes":[{"secret":{"secretName":names["pod"]}}]}}]}
            if args[0:2] == ["get","secrets"]:
                return {"items":[{"metadata":{"name":n,"uid":"uid-"+k}} for k,n in names.items()] + [{"metadata":{"name":"runtime-env","uid":"baseline"}}]}
            calls.append((args,body));return {}
        kube.run = run
        kube.collect_unused_secrets()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][2], "/api/v1/namespaces/koth-demo/secrets/"+names["unused"])
        self.assertEqual(calls[0][1]["preconditions"], {"uid":"uid-unused"})

    def test_publication_updates_require_opt_in_and_same_approved_ghcr_repository(self):
        changed = copy.deepcopy(self.desired)
        changed.update(source_revision="c" * 40, publication_id=identifier())
        changed["settings"]["containers"][0]["image"] = self.game["containers"]["service"]["image"].replace("a" * 64, "b" * 64)
        with self.assertRaises(agent.Fault): agent.validate_desired(self.config, self.game, changed)
        self.game["allow_publications"] = True
        agent.validate_config(self.config)
        agent.validate_desired(self.config, self.game, changed)
        changed["settings"]["containers"][0]["image"] = changed["settings"]["containers"][0]["image"].replace("koth-demo", "koth-other")
        with self.assertRaises(agent.Fault): agent.validate_desired(self.config, self.game, changed)

    def test_publication_template_keeps_original_isolation_resource_and_volume_profile(self):
        self.game["allow_publications"] = True
        self.desired.update(publication_id=identifier(), source_revision="c" * 40)
        self.desired["settings"]["containers"][0]["image"] = self.desired["settings"]["containers"][0]["image"].replace("a" * 64, "b" * 64)
        agent.validate_desired(self.config, self.game, self.desired)
        updated = self.kube.template(self.kube.original, self.desired)
        self.assertEqual(updated["spec"]["containers"][0]["image"], self.desired["settings"]["containers"][0]["image"])
        original = copy.deepcopy(self.kube.original)
        clean = copy.deepcopy(updated)
        for item in (original, clean):
            item["metadata"].pop("annotations", None)
            item["spec"]["containers"][0].pop("envFrom", None)
            item["spec"]["containers"][0].pop("image")
        self.assertEqual(original, clean)

    def test_image_preparation_failure_does_not_mutate_a_running_template(self):
        before = copy.deepcopy(self.kube.current)
        with patch.object(self.kube, "ensure_images", side_effect=agent.Fault("IMAGE_PREPARATION_FAILED")):
            self.assertEqual(self.worker.tick(), "rejected")
        self.assertEqual(before, self.kube.current)
        self.assertEqual(self.kube.patches, [])
        self.assertEqual(self.api.events[-1][1:], ("FAILED", "IMAGE_PREPARATION_FAILED"))

    def test_changed_source_without_publication_is_rejected_even_when_opted_in(self):
        self.game["allow_publications"] = True
        self.desired["source_revision"] = "c" * 40
        with self.assertRaises(agent.Fault): agent.validate_desired(self.config, self.game, self.desired)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, "Linux root-only journal semantics")
    def test_journal_is_atomic_private_and_rejects_readable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = agent.Journal(directory, self.game["challenge_id"])
            journal.write({"application_id": self.desired["application_id"], "phase": "healthy"})
            self.assertEqual(journal.read()["phase"], "healthy")
            self.assertEqual(journal.path.stat().st_mode & 0o777, 0o600)
            journal.path.chmod(0o644)
            with self.assertRaises(ValueError): journal.read()


if __name__ == "__main__":
    unittest.main()
