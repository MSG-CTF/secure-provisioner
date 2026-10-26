#!/usr/bin/python3 -I
"""Root-only, static-policy raw/PREROUTING guard for Gateway-only TCP NodePorts.

No shell is used. Never flush an attached chain. An apply failure keeps any
already-attached protection in place. There is intentionally no automatic undo.
"""
import argparse
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

CONFIG_PATH = Path("/etc/secure-provisioner/gateway-nodeport-firewall.json")
LOCK_DIR = Path("/run/msgctf-gateway-nodeport-firewall")
LOCK_PATH = LOCK_DIR / "operation.lock"
CHAIN = {4: "MSGCTF_GWNP4", 6: "MSGCTF_GWNP6"}
BINARIES = {4: "/usr/sbin/iptables", 6: "/usr/sbin/ip6tables"}
JUMP_TAG = "msgctf-gateway-nodeports-v1"
SOURCE_TAG = "msgctf-gateway-source-v1"
DENY_TAG = "msgctf-gateway-deny-v1"
OWN_TAGS = {JUMP_TAG, SOURCE_TAG, DENY_TAG}


class FirewallError(Exception):
    """A checked precondition or kernel operation failed."""


def validate_config(value):
    keys = {"schema_version", "gateway_ipv4_sources", "gateway_ipv6_sources"}
    if not isinstance(value, dict) or set(value) != keys:
        raise FirewallError("configuration must contain exactly the documented keys")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise FirewallError("unsupported schema_version")
    result = {"schema_version": 1}
    for family in (4, 6):
        key = f"gateway_ipv{family}_sources"
        sources = value[key]
        if not isinstance(sources, list) or len(sources) > 16 or (family == 4 and not sources):
            raise FirewallError(f"{key}: expected {'1..16' if family == 4 else '0..16'} sources")
        networks = []
        for source in sources:
            if not isinstance(source, str) or source != source.strip() or "%" in source:
                raise FirewallError(f"{key}: invalid address syntax")
            try:
                network = ipaddress.ip_network(source, strict=True)
            except ValueError as exc:
                raise FirewallError(f"{key}: invalid address or noncanonical CIDR") from exc
            minimum = 28 if family == 4 else 124
            if network.version != family or network.prefixlen < minimum:
                raise FirewallError(f"{key}: use IPv{family} global hosts or explicit /{minimum}+ CIDRs")
            for address in (network.network_address, network.broadcast_address):
                if not address.is_global or address.is_multicast or address.is_reserved or address.is_loopback or address.is_link_local or address.is_unspecified:
                    raise FirewallError(f"{key}: only global unicast addresses are allowed")
            if any(network.overlaps(other) for other in networks):
                raise FirewallError(f"{key}: duplicate or overlapping source ranges")
            networks.append(network)
        result[key] = sorted(str(network) for network in networks)
    return result


def _assert_secure_metadata(metadata, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise FirewallError("path must be root-owned, correctly typed, and not group/world-writable")
    if not directory and metadata.st_nlink != 1:
        raise FirewallError("file must have exactly one hard link")


def _check_parent_directories(path):
    for parent in reversed(path.parents):
        _assert_secure_metadata(parent.lstat(), directory=True)


def _no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise FirewallError("duplicate JSON key")
        value[key] = item
    return value


def load_config():
    _check_parent_directories(CONFIG_PATH)
    fd = os.open(CONFIG_PATH, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        _assert_secure_metadata(os.fstat(fd))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(16385)
        if len(payload) > 16384:
            raise FirewallError("configuration exceeds 16 KiB")
        try:
            return validate_config(json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_keys))
        except (UnicodeError, ValueError) as exc:
            raise FirewallError("configuration must be valid UTF-8 JSON") from exc
    finally:
        os.close(fd)


@contextmanager
def operation_lock():
    import fcntl  # Linux-only execution; pure policy tests remain portable.
    _check_parent_directories(LOCK_DIR)
    try:
        LOCK_DIR.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _assert_secure_metadata(LOCK_DIR.lstat(), directory=True)
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        _assert_secure_metadata(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class KernelBackend:
    def _run(self, family, args):
        binary = BINARIES[family]
        # resolve() permits the root-managed alternatives symlinks used by Debian.
        resolved = Path(binary).resolve(strict=True)
        _check_parent_directories(resolved)
        _assert_secure_metadata(resolved.stat())
        result = subprocess.run(
            [binary, "-w", "5", "-t", "raw", *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=30, check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode:
            raise FirewallError(f"IPv{family} iptables operation failed ({result.returncode}): {result.stderr.strip()}")
        return result.stdout

    def read(self, family):
        return self._run(family, ["-S"])

    def mutate(self, family, args):
        self._run(family, args)


def parse_table(output):
    chains = {}
    for line in output.splitlines():
        tokens = shlex.split(line)
        if not tokens:
            continue
        if tokens[0] in ("-N", "-P") and len(tokens) == (2 if tokens[0] == "-N" else 3):
            if tokens[1] in chains:
                raise FirewallError("duplicate raw-table chain declaration")
            chains[tokens[1]] = []
        elif len(tokens) >= 3 and tokens[0] == "-A" and tokens[1] in chains:
            chains[tokens[1]].append(tokens[2:])
        else:
            raise FirewallError("unrecognized raw-table listing")
    if "PREROUTING" not in chains:
        raise FirewallError("raw PREROUTING chain is unavailable")
    return chains


def canonical_rule(rule):
    normalized = list(rule)
    if "-s" in normalized:
        index = normalized.index("-s") + 1
        try:
            normalized[index] = str(ipaddress.ip_network(normalized[index], strict=True))
        except (ValueError, IndexError) as exc:
            raise FirewallError("invalid source in existing owned rule") from exc
    return normalized


class Engine:
    def __init__(self, config, backend):
        self.config = validate_config(config)
        self.backend = backend

    def chain_rules(self, family):
        return [["-s", source, "-m", "comment", "--comment", SOURCE_TAG, "-j", "RETURN"]
                for source in self.config[f"gateway_ipv{family}_sources"]] + [
                    ["-m", "comment", "--comment", DENY_TAG, "-j", "DROP"]]

    def jump_rule(self, family):
        return ["-p", "tcp", "-m", "tcp", "--dport", "30000:32767", "-m", "addrtype", "--dst-type", "LOCAL", "-m", "comment", "--comment", JUMP_TAG, "-j", CHAIN[family]]

    def inspect(self, family):
        table = parse_table(self.backend.read(family))
        chain = CHAIN[family]
        if CHAIN[6 if family == 4 else 4] in table:
            raise FirewallError(f"IPv{family}: owned chain name exists in the wrong address family")
        present = chain in table
        if present and [canonical_rule(rule) for rule in table[chain]] != self.chain_rules(family):
            raise FirewallError(f"IPv{family}: unexpected owned chain contents; refusing modification")
        references = []
        for owner, rules in table.items():
            for index, rule in enumerate(rules):
                for flag in ("-j", "-g"):
                    if flag in rule and rule.index(flag) + 1 < len(rule) and rule[rule.index(flag) + 1] in CHAIN.values():
                        if owner != "PREROUTING" or rule != self.jump_rule(family) or index != 0:
                            raise FirewallError(f"IPv{family}: unexpected owned-chain reference or PREROUTING order")
                        references.append((owner, index))
                for position, token in enumerate(rule[:-1]):
                    if token == "--comment" and rule[position + 1] in OWN_TAGS:
                        if not ((owner == chain and canonical_rule(rule) in self.chain_rules(family)) or (owner == "PREROUTING" and rule == self.jump_rule(family) and index == 0)):
                            raise FirewallError(f"IPv{family}: unexpected owned rule marker")
        if len(references) > 1 or (references and not present):
            raise FirewallError(f"IPv{family}: inconsistent owned-chain attachment")
        return present, bool(references)

    def preflight(self):
        # Both families are checked before the first mutation, including remove.
        return {family: self.inspect(family) for family in (4, 6)}

    def verify(self):
        states = self.preflight()
        if any(state != (True, True) for state in states.values()):
            raise FirewallError("both IPv4 and IPv6 guards must be populated and attached first in raw PREROUTING")

    def apply(self):
        states = self.preflight()
        for family in (4, 6):
            present, attached = states[family]
            if not present:
                self.backend.mutate(family, ["-N", CHAIN[family]])
                for rule in self.chain_rules(family):
                    self.backend.mutate(family, ["-A", CHAIN[family], *rule])
                # Confirm complete contents before exposing the new chain to traffic.
                if self.inspect(family) != (True, False):
                    raise FirewallError(f"IPv{family}: new chain failed pre-attachment verification")
            if not attached:
                self.backend.mutate(family, ["-I", "PREROUTING", "1", *self.jump_rule(family)])
        self.verify()

    def remove(self, confirmed=False):
        if confirmed is not True:
            raise FirewallError("remove requires operator confirmation: routes clean and no live bindings")
        states = self.preflight()
        for family in (4, 6):
            present, attached = states[family]
            if attached:
                self.backend.mutate(family, ["-D", "PREROUTING", *self.jump_rule(family)])
            if present:
                # Recheck detachment and expected contents before deleting only our chain.
                if self.inspect(family) != (True, False):
                    raise FirewallError(f"IPv{family}: chain is still attached or changed; leaving it intact")
                self.backend.mutate(family, ["-F", CHAIN[family]])
                self.backend.mutate(family, ["-X", CHAIN[family]])
        if any(state != (False, False) for state in self.preflight().values()):
            raise FirewallError("owned firewall removal verification failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("apply", "verify", "remove"))
    parser.add_argument("--operator-confirm-routes-clean-and-no-live-bindings", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if os.name != "posix" or os.geteuid() != 0:
            raise FirewallError("must run as root on Linux")
        if arguments.operation != "remove" and arguments.operator_confirm_routes_clean_and_no_live_bindings:
            raise FirewallError("operator confirmation is accepted only with remove")
        config = load_config()
        with operation_lock():
            engine = Engine(config, KernelBackend())
            if arguments.operation == "remove":
                engine.remove(confirmed=arguments.operator_confirm_routes_clean_and_no_live_bindings)
            else:
                getattr(engine, arguments.operation)()
        print(json.dumps({"operation": arguments.operation, "status": "ok", "table": "raw", "tcp_nodeports": "30000:32767", "ipv4_sources": config["gateway_ipv4_sources"], "ipv6_sources": config["gateway_ipv6_sources"]}, sort_keys=True))
        return 0
    except (FirewallError, OSError, subprocess.SubprocessError) as exc:
        print(f"msgctf gateway NodePort firewall: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
