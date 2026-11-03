"""Contract tests: an in-memory raw-table kernel boundary, no host firewall calls."""
import copy
import importlib.util
import ipaddress
from pathlib import Path
import shlex
import unittest

SPEC = importlib.util.spec_from_file_location("firewall", Path(__file__).with_name("msgctf-gateway-nodeport-firewall.py"))
fw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fw)

CHAIN4 = "MSGCTF_GWNP4"
CHAIN6 = "MSGCTF_GWNP6"


def config(**changes):
    value = {"schema_version": 1, "gateway_ipv4_sources": ["34.172.6.196/32"], "gateway_ipv6_sources": []}
    value.update(changes)
    return fw.validate_config(value)


class RawKernel:
    """Only replaces the external iptables process; records actual table side effects."""
    def __init__(self):
        self.tables = {family: {"PREROUTING": [["-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"]], "OUTPUT": [], "UNRELATED": [["-j", "RETURN"]]} for family in (4, 6)}
        self.mutations = []
        self.fail_on = None

    def read(self, family):
        table = self.tables[family]
        lines = ["-P PREROUTING ACCEPT", "-P OUTPUT ACCEPT"]
        lines += ["-N " + chain for chain in table if chain not in ("PREROUTING", "OUTPUT")]
        lines += [shlex.join(["-A", chain] + rule) for chain, rules in table.items() for rule in rules]
        return "\n".join(lines) + "\n"

    def validate_ingress_interface(self, interface):
        if interface != "ens4":
            raise fw.FirewallError("the fixture has one hardware NIC, ens4")

    def mutate(self, family, args):
        if self.fail_on and self.fail_on(family, args):
            raise fw.FirewallError("simulated kernel failure")
        table = self.tables[family]
        op, chain, *rest = args
        if op == "-N":
            if chain in table:
                raise AssertionError("chain already exists")
            table[chain] = []
        elif op == "-A":
            table[chain].append(rest)
        elif op == "-I":
            index, *rule = rest
            table[chain].insert(int(index) - 1, rule)
        elif op == "-D":
            table[chain].remove(rest)
        elif op == "-F":
            for rules in table.values():
                if any("-j" in rule and rule[rule.index("-j") + 1] == chain for rule in rules):
                    raise AssertionError("attempted flush of attached chain")
            table[chain].clear()
        elif op == "-X":
            if table[chain]:
                raise AssertionError("delete nonempty chain")
            del table[chain]
        else:
            raise AssertionError(args)
        self.mutations.append((family, tuple(args), copy.deepcopy(self.tables)))

    def verdict(self, family, source, port, protocol="tcp", destination_local=True, interface="ens4"):
        def traverse(chain):
            for rule in self.tables[family][chain]:
                if "-i" in rule and rule[rule.index("-i") + 1] != interface:
                    continue
                if "-p" in rule and rule[rule.index("-p") + 1] != protocol:
                    continue
                if "--dst-type" in rule and rule[rule.index("--dst-type") + 1] == "LOCAL" and not destination_local:
                    continue
                if "--dport" in rule:
                    lo, _, hi = rule[rule.index("--dport") + 1].partition(":")
                    if not int(lo) <= port <= int(hi or lo):
                        continue
                if "-s" in rule and ipaddress.ip_address(source) not in ipaddress.ip_network(rule[rule.index("-s") + 1]):
                    continue
                target = rule[rule.index("-j") + 1]
                if target in ("RETURN", "DROP", "ACCEPT"):
                    return target
                result = traverse(target)
                if result != "RETURN":
                    return result
            return "RETURN"
        result = traverse("PREROUTING")
        return "ACCEPT" if result == "RETURN" else result


class ConfigTests(unittest.TestCase):
    def test_broad_private_special_and_malformed_sources_fail_closed(self):
        # Removing public/narrow validation would permit these unsafe allowances.
        for value in ("0.0.0.0/0", "34.172.6.0/24", "10.0.0.1", "127.0.0.1", "100.64.0.1", "224.0.0.1", "192.0.2.1", "34.172.6.196/28", "34.172.6.196;id", "34.172.6.196 "):
            with self.subTest(value=value), self.assertRaises(fw.FirewallError):
                config(gateway_ipv4_sources=[value])
        for value in ("::/0", "2001:4860::/64", "::1", "fc00::1", "ff02::1", "fe80::1%eth0", "2001:db8::1"):
            with self.subTest(value=value), self.assertRaises(fw.FirewallError):
                config(gateway_ipv6_sources=[value])

    def test_valid_hosts_normalize_and_narrow_networks_are_explicit(self):
        self.assertEqual(config(gateway_ipv4_sources=["34.172.6.196"])["gateway_ipv4_sources"], ["34.172.6.196/32"])
        self.assertEqual(config(gateway_ipv4_sources=["34.172.6.192/28"])["gateway_ipv4_sources"], ["34.172.6.192/28"])
        self.assertEqual(config(gateway_ipv6_sources=["2606:4700:4700::1111"])["gateway_ipv6_sources"], ["2606:4700:4700::1111/128"])

    def test_unknown_fields_empty_v4_duplicates_overlaps_wrong_family_rejected(self):
        for changes in ({"ports": "22:65535"}, {"gateway_ipv4_sources": []}, {"schema_version": True}, {"gateway_ipv4_sources": ["2606:4700::1"]}, {"gateway_ipv4_sources": ["34.172.6.196", "34.172.6.196/32"]}, {"gateway_ipv4_sources": ["34.172.6.192/28", "34.172.6.196"]}):
            with self.subTest(changes=changes), self.assertRaises(fw.FirewallError):
                config(**changes)


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.kernel = RawKernel()
        self.engine = fw.Engine(config(), self.kernel)

    def test_only_gateway_tcp_nodeports_return_other_sources_drop(self):
        self.engine.apply()
        for port in (30000, 31854, 32767):
            self.assertEqual(self.kernel.verdict(4, "34.172.6.196", port), "ACCEPT")
            self.assertEqual(self.kernel.verdict(4, "8.8.8.8", port), "DROP")
        self.assertEqual(self.kernel.tables[4][CHAIN4][-1][-1], "DROP")

    def test_ipv6_without_approved_source_drops_all_nodeports(self):
        self.engine.apply()
        for source in ("2606:4700:4700::1111", "::1"):
            self.assertEqual(self.kernel.verdict(6, source, 31854), "DROP")
        self.assertEqual(len(self.kernel.tables[6][CHAIN6]), 1)

    def test_unrelated_ports_udp_and_chains_unchanged(self):
        previous = copy.deepcopy(self.kernel.tables)
        self.engine.apply()
        for family, source in ((4, "8.8.8.8"), (6, "2606:4700::1")):
            for port in (22, 443, 6443, 29999, 32768, 5432):
                self.assertEqual(self.kernel.verdict(family, source, port), "ACCEPT")
            self.assertEqual(self.kernel.verdict(family, source, 31854, "udp"), "ACCEPT")
            self.assertEqual(self.kernel.tables[family]["OUTPUT"], previous[family]["OUTPUT"])
            self.assertEqual(self.kernel.tables[family]["UNRELATED"], previous[family]["UNRELATED"])
            self.assertEqual(self.kernel.tables[family]["PREROUTING"][1:], previous[family]["PREROUTING"])

    def test_forwarded_private_pod_and_clusterip_ports_bypass_nodeport_guard(self):
        # A missing LOCAL destination match drops unrelated private forwarding.
        self.engine.apply()
        for family, source in ((4, "10.42.1.5"), (6, "fd00::5")):
            for port in (30000, 31337, 31854, 32767):
                self.assertEqual(self.kernel.verdict(family, source, port, destination_local=False), "ACCEPT")
                self.assertEqual(self.kernel.verdict(family, source, port, destination_local=True), "DROP")

    def test_chain_fully_populated_before_first_prerouting_jump(self):
        self.engine.apply()
        attachments = [(family, snapshot) for family, args, snapshot in self.kernel.mutations if args[:2] == ("-I", "PREROUTING")]
        self.assertEqual(len(attachments), 2)
        for family, snapshot in attachments:
            chain = CHAIN4 if family == 4 else CHAIN6
            self.assertEqual(snapshot[family][chain][-1][-1], "DROP")
            self.assertEqual(len(snapshot[family][chain]), 2 if family == 4 else 1)
            self.assertEqual(snapshot[family]["PREROUTING"][0][-1], chain)

    def test_repeat_apply_and_verify_do_not_mutate(self):
        self.engine.apply()
        self.assertIn(CHAIN4, self.kernel.tables[4])
        self.kernel.mutations.clear()
        self.engine.apply()
        self.engine.verify()
        self.assertEqual(self.kernel.mutations, [])

    def test_either_family_tamper_fails_before_any_mutation(self):
        for family, chain in ((4, CHAIN4), (6, CHAIN6)):
            kernel = RawKernel()
            kernel.tables[family][chain] = [["-j", "ACCEPT"]]
            before = copy.deepcopy(kernel.tables)
            with self.subTest(family=family), self.assertRaises(fw.FirewallError):
                fw.Engine(config(), kernel).apply()
            self.assertEqual(kernel.mutations, [])
            self.assertEqual(kernel.tables, before)

    def test_missing_duplicate_moved_or_foreign_reference_fails_verification(self):
        mutators = [
            lambda k: k.tables[4][CHAIN4].pop(),
            lambda k: k.tables[4]["PREROUTING"].append(copy.deepcopy(k.tables[4]["PREROUTING"][0])),
            lambda k: k.tables[4]["PREROUTING"].reverse(),
            lambda k: k.tables[4]["UNRELATED"].append(["-j", CHAIN4]),
        ]
        for mutate in mutators:
            kernel = RawKernel()
            engine = fw.Engine(config(), kernel)
            engine.apply()
            mutate(kernel)
            kernel.mutations.clear()
            with self.subTest(mutate=mutate), self.assertRaises(fw.FirewallError):
                engine.verify()
            with self.assertRaises(fw.FirewallError):
                engine.apply()
            self.assertEqual(kernel.mutations, [])

    def test_missing_jump_fails_verify_but_complete_detached_chain_recovers(self):
        self.engine.apply()
        self.kernel.tables[4]["PREROUTING"].pop(0)
        with self.assertRaises(fw.FirewallError):
            self.engine.verify()
        self.engine.apply()
        self.engine.verify()

    def test_safe_remove_needs_confirmation_and_preserves_unrelated_rules(self):
        initial = copy.deepcopy(self.kernel.tables)
        self.engine.apply()
        with self.assertRaises(fw.FirewallError):
            self.engine.remove(confirmed=False)
        self.engine.verify()
        self.engine.remove(confirmed=True)
        self.assertEqual(self.kernel.tables, initial)
        self.kernel.mutations.clear()
        self.engine.remove(confirmed=True)
        self.assertEqual(self.kernel.mutations, [])

    def test_owned_name_in_wrong_family_is_refused_before_mutation(self):
        self.kernel.tables[4][CHAIN6] = [["-j", "ACCEPT"]]
        with self.assertRaises(fw.FirewallError):
            self.engine.apply()
        self.assertEqual(self.kernel.mutations, [])

    def test_remove_rejects_tamper_before_deleting_any_family(self):
        self.engine.apply()
        self.kernel.tables[6][CHAIN6].insert(0, ["-j", "ACCEPT"])
        self.kernel.mutations.clear()
        with self.assertRaises(fw.FirewallError):
            self.engine.remove(confirmed=True)
        self.assertEqual(self.kernel.mutations, [])

    def test_failed_apply_does_not_remove_already_installed_protection(self):
        self.kernel.fail_on = lambda family, args: family == 6 and args[0] == "-N"
        with self.assertRaises(fw.FirewallError):
            self.engine.apply()
        self.assertEqual(self.kernel.verdict(4, "8.8.8.8", 31854), "DROP")
        self.assertFalse(any(args[0] in ("-F", "-D", "-X") for _, args, _ in self.kernel.mutations))


class ScopedIngressTests(unittest.TestCase):
    def test_snat_reply_to_local_nodeport_number_bypasses_external_guard(self):
        kernel = RawKernel()
        fw.Engine(config(ingress_interface="ens4"), kernel).apply()
        for family, gateway, pod, stranger in ((4, "34.172.6.196", "10.42.0.72", "8.8.8.8"), (6, "2606:4700::1", "fd00::72", "2606:4700::2")):
            for port in (30000, 30725, 31696, 32767):
                self.assertEqual(kernel.verdict(family, pod, port, destination_local=True, interface="cni0"), "ACCEPT")
                self.assertEqual(kernel.verdict(family, stranger, port, interface="ens4"), "DROP")
        self.assertEqual(kernel.verdict(4, "34.172.6.196", 31696, interface="ens4"), "ACCEPT")

    def test_legacy_migration_keeps_external_protection_at_every_mutation(self):
        kernel = RawKernel()
        fw.Engine(config(), kernel).apply()
        kernel.mutations.clear()
        engine = fw.Engine(config(ingress_interface="ens4"), kernel)
        with self.assertRaises(fw.FirewallError):
            engine.verify()
        engine.apply()
        for _, _, snapshot in kernel.mutations:
            point = RawKernel()
            point.tables = snapshot
            for family, outsider in ((4, "8.8.8.8"), (6, "2606:4700::2")):
                self.assertEqual(point.verdict(family, outsider, 31696), "DROP")
        engine.verify()
        self.assertEqual(kernel.verdict(4, "10.42.0.72", 31696, interface="cni0"), "ACCEPT")
        before = copy.deepcopy(kernel.tables)
        kernel.mutations.clear()
        engine.apply()
        self.assertEqual(kernel.mutations, [])
        self.assertEqual(kernel.tables, before)

    def test_interrupted_legacy_removal_recovers_without_opening_external_ports(self):
        kernel = RawKernel()
        fw.Engine(config(), kernel).apply()
        engine = fw.Engine(config(ingress_interface="ens4"), kernel)
        kernel.fail_on = lambda family, args: family == 4 and args[0] == "-D"
        with self.assertRaises(fw.FirewallError):
            engine.apply()
        self.assertEqual(kernel.verdict(4, "8.8.8.8", 31696), "DROP")
        kernel.fail_on = None
        engine.apply()
        engine.verify()
        self.assertEqual(kernel.verdict(4, "10.42.0.72", 31696, interface="cni0"), "ACCEPT")

    def test_wrong_or_nonphysical_interface_fails_before_any_mutation(self):
        for interface in ("lo", "cni0", "veth123", "ens5"):
            kernel = RawKernel()
            fw.Engine(config(), kernel).apply()
            kernel.mutations.clear()
            with self.assertRaises(fw.FirewallError):
                fw.Engine(config(ingress_interface=interface), kernel).apply()
            self.assertEqual(kernel.mutations, [])
            self.assertEqual(kernel.verdict(4, "8.8.8.8", 31696), "DROP")

    def test_interface_globs_and_shell_syntax_are_not_accepted(self):
        for interface in ("", "*", "ens+", "ens4;id", " ens4", "--jump", True, [], "a" * 16):
            with self.subTest(interface=interface), self.assertRaises(fw.FirewallError):
                config(ingress_interface=interface)

    def test_tampered_legacy_guard_is_not_migrated(self):
        kernel = RawKernel()
        fw.Engine(config(), kernel).apply()
        kernel.tables[6][CHAIN6].append(["-j", "ACCEPT"])
        kernel.mutations.clear()
        with self.assertRaises(fw.FirewallError):
            fw.Engine(config(ingress_interface="ens4"), kernel).apply()
        self.assertEqual(kernel.mutations, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
