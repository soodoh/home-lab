#!/usr/bin/python3 -IBS
"""Offline synthetic parser/file/CLI cases; optional local builtin-only Tofu fixture.

No production model, collection, apply, import, backend or external provider use.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
SCRIPT = ROOT / "scripts/controller/tailscale-access-evidence.py"
HELPER = SCRIPT.with_name("tailscale-policy.py")


def load(path):
    module = types.ModuleType(path.stem)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


diag = load(SCRIPT)
reader = diag.PrivateReads()
try:
    policy_helper = diag.load_helper(reader)
finally:
    reader.close()


POLICY = {
    "tagOwners": {"tag:fixture": ["autogroup:admin"]},
    "grants": [{"src": ["autogroup:owner"], "dst": ["tag:fixture"], "ip": ["tcp:22"]}],
    "ssh": [{"action": "accept", "src": ["autogroup:owner"], "dst": ["tag:fixture"], "users": ["fixture"]}],
    "tests": [{"src": "fixture@example.invalid", "proto": "tcp", "accept": ["tag:fixture:22"], "deny": ["tag:fixture:23"]}],
    "sshTests": [{"src": "fixture@example.invalid", "dst": ["tag:fixture"], "accept": ["fixture"], "deny": ["root"]}],
}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def values(policy=POLICY):
    raw = encoded(policy)
    input_value = {"policy_json": raw.decode(), "policy_sha256": diag.sha(raw)}
    return {"id": "synthetic-id", "input": input_value, "output": copy.deepcopy(input_value), "triggers_replace": None}


def fixture_plan():
    """Synthetic decoded parser fixture matching locally observed Tofu 1.12.5 JSON."""
    value = values()
    resource = {**diag.DESCRIPTOR, "schema_version": 0, "values": value,
                "sensitive_values": {"input": {}, "output": {}}}
    root = {"root_module": {"resources": [resource]}}
    return copy.deepcopy({
        "format_version": "1.2", "terraform_version": "1.12.5",
        "planned_values": root,
        "resource_changes": [{**diag.DESCRIPTOR, "change": {
            "actions": ["no-op"], "before": value, "after": value, "after_unknown": {},
            "before_sensitive": {"input": {}, "output": {}}, "after_sensitive": {"input": {}, "output": {}}}}],
        "prior_state": {"format_version": "1.0", "terraform_version": "1.12.5", "values": root},
        "configuration": {"provider_config": {"terraform": {"name": "terraform", "full_name": "terraform.io/builtin/terraform"}},
                          "root_module": {"resources": [{"address": "terraform_data.tailscale_policy", "mode": "managed",
                              "type": "terraform_data", "name": "tailscale_policy", "provider_config_key": "terraform",
                              "expressions": {"input": {"constant_value": value["input"]}}, "schema_version": 0,
                              "count_expression": {"constant_value": 1}}]}},
        "timestamp": "2026-01-01T00:00:00Z", "errored": False,
    })


def header(body, etag='"fixture-etag"'):
    return ("HTTP/2 200\r\nContent-Type: application/json\r\nETag: " + etag +
            "\r\nContent-Length: " + str(len(body)) + "\r\n\r\n").encode()


def inputs(plan=None):
    body = encoded(POLICY)
    return {"plan": encoded(fixture_plan()) if plan is None else plan,
            "expected_policy": body, "live_before": body, "live_after": body,
            "headers_before": header(body), "headers_after": header(body)}


def verify(data):
    return diag.verify(data, diag.sha(data["expected_policy"]), policy_helper)


def set_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


class SemanticTests(unittest.TestCase):
    def assertRejected(self, data):
        output = verify(data)
        self.assertFalse(output["content_consistent"])
        self.assertFalse(output["authorized"])
        self.assertFalse(output["admission_eligible"])
        self.assertEqual(output["blockers"], diag.BLOCKERS)
        self.assertTrue(output["errors"])
        self.assertLess(len(diag.canonical(output)), 4096)
        return output

    def test_actual_helper_and_noop_content_only(self):
        self.assertEqual(diag.sha(HELPER.read_bytes()), diag.HELPER_SHA256)
        data = inputs()
        output = verify(data)
        self.assertTrue(output["content_consistent"], output)
        self.assertEqual(output["canonical_policy_sha256"], policy_helper.canonical_policy_sha256(POLICY))
        self.assertEqual(output["inputs"], {k: {"sha256": hashlib.sha256(v).hexdigest(), "size": len(v)} for k, v in data.items()})
        self.assertEqual(policy_helper.policy_from_plan(fixture_plan(), "before"), POLICY)
        for bad in ('{"grants":[],"grants":[]}', '{"grants":NaN}'):
            with self.assertRaises(policy_helper.PolicyError):
                policy_helper.parse_policy_json(bad)
        # Exact independent bytes differ from semantic canonicalization; ETag is not leaked.
        data["expected_policy"] = json.dumps(POLICY, indent=2).encode() + b"\n"
        data["live_after"] = json.dumps(POLICY, sort_keys=True).encode()
        data["headers_after"] = header(data["live_after"])
        self.assertTrue(verify(data)["content_consistent"])
        self.assertNotIn(b"fixture", diag.canonical(verify(data)))
        self.assertFalse(diag.verify(data, "0" * 64, policy_helper)["content_consistent"])
        for digest in (True, "A" * 64, "", "a" * 63):
            self.assertFalse(diag.verify(data, digest, policy_helper)["content_consistent"])

    def test_plan_mutation_matrix(self):
        change = ("resource_changes", 0, "change")
        mutations = [
            (("resource_changes",), []), (("resource_changes",), [{}, {}]),
            (("resource_changes", 0, "address"), "module.alias.terraform_data.tailscale_policy[0]"),
            (("resource_changes", 0, "address"), "terraform_data.tailscale_policy"),
            (("resource_changes", 0, "name"), "other"), (("resource_changes", 0, "mode"), "data"),
            (("resource_changes", 0, "type"), "tailscale_acl"), (("resource_changes", 0, "index"), False),
            (("resource_changes", 0, "index"), 1), (("resource_changes", 0, "provider_name"), "other"),
            (("resource_changes", 0, "module_address"), "module.alias"),
            (("resource_changes", 0, "previous_address"), "terraform_data.old[0]"),
            (change + ("importing",), {"id": "synthetic"}), (change + ("importing",), None),
            (change + ("after_unknown",), {"input": {"policy_json": True}}),
            (change + ("after_unknown",), None), (change + ("after_unknown",), {"input": False}),
            (change + ("after_sensitive",), True), (change + ("before",), None),
            (change + ("after", "id"), "different"), (change + ("before", "id"), None),
            (change + ("after", "triggers_replace"), []),
            (change + ("after", "output"), {}), (change + ("after", "input", "policy_json"), {}),
            (change + ("before", "input", "policy_sha256"), "0" * 64),
            (change + ("replace_paths",), []), (("resource_drift",), [{}]),
            (("deferred_changes",), [{}]), (("checks",), [{"status": "unknown"}]),
            (("complete",), False), (("errored",), True), (("applyable",), True),
            (("variables",), {"tailscale_enable_management": {"value": False}}),
            (("variables",), {"tailscale_enable_management": {"value": 1}}),
            (("output_changes",), {"unexpected": {"actions": ["no-op"], "before": 1, "after": 1}}),
            (("output_changes",), {"unexpected": {"actions": ["update"], "before": 1, "after": 2}}),
            (("planned_values", "outputs"), {"unexpected": {"value": 1}}),
            (("prior_state", "values", "outputs"), {"unexpected": {"value": 1}}),
            (("planned_values", "root_module", "child_modules"), []),
            (("prior_state", "values", "root_module", "resources"), []),
            (("planned_values", "root_module", "resources", 0, "values", "id"), "inconsistent"),
            (("planned_values", "root_module", "resources", 0, "schema_version"), False),
            (("configuration", "root_module", "module_calls"), {}),
            (("configuration", "root_module", "resources", 0, "provider_config_key"), "terraform.alias"),
            (("configuration", "root_module", "resources", 0, "count_expression"), {"constant_value": 0}),
            (("configuration", "root_module", "resources", 0, "expressions", "input"), {"constant_value": {}}),
            (("format_version",), "9.0"), (("terraform_version",), True), (("timestamp",), None),
            (("unrelated_stdout",), "No changes. Your infrastructure matches the configuration."),
        ]
        mutations.extend((change + ("actions",), actions) for actions in ([], ["read"], ["create"], ["update"], ["delete"], ["delete", "create"], ["no-op", "read"]))
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                # JSON roundtrip breaks aliases in the synthetic factory.
                plan = json.loads(encoded(fixture_plan()))
                set_path(plan, path, replacement)
                self.assertRejected(inputs(encoded(plan)))
        for section in ("resource_changes", "planned_values", "prior_state", "configuration"):
            plan = fixture_plan(); del plan[section]
            self.assertRejected(inputs(encoded(plan)))
        plan = fixture_plan(); plan["resource_changes"].append(copy.deepcopy(plan["resource_changes"][0]))
        self.assertRejected(inputs(encoded(plan)))
        for raw in (b"No changes. Your infrastructure matches the configuration.", b"{}", b"[]"):
            self.assertRejected(inputs(raw))

    def test_unused_provider_is_bounded_opaque_not_dependency_proof(self):
        # Synthetic metadata extension, NOT observed by the builtin-only Tofu run.
        plan = fixture_plan()
        providers = plan["configuration"]["provider_config"]
        providers["tailscale"] = {"unverified": {"expressions": {"credential": "PRIVATE-PROVIDER-SECRET"}}}
        output = verify(inputs(encoded(plan)))
        self.assertTrue(output["content_consistent"], output)
        self.assertIn("unused-root-tailscale-provider-metadata-not-verified", output["limitations"])
        self.assertNotIn(b"PRIVATE", diag.canonical(output))
        self.assertFalse(output["authorized"])
        self.assertFalse(output["admission_eligible"])
        self.assertEqual(output["blockers"], diag.BLOCKERS)
        bad_entries = [None, [], "opaque", False, {}, {"alias": "secret"}, {"module_address": "module.secret"},
                       {"nested": [{"ModuleCalls": {}}]}, {"nested": "tailscale.secret"},
                       {"nested": "module.secret"}, {"too_big": "s" * 16384}]
        for entry in bad_entries:
            candidate = copy.deepcopy(plan)
            candidate["configuration"]["provider_config"]["tailscale"] = entry
            self.assertRejected(inputs(encoded(candidate)))
        for key in ("tailscale.alias", "module.secret:tailscale", "extra"):
            candidate = copy.deepcopy(plan)
            candidate["configuration"]["provider_config"][key] = {"name": "unused"}
            self.assertRejected(inputs(encoded(candidate)))
        for path in (("configuration", "root_module", "resources", 0, "provider_config_key"),
                     ("resource_changes", 0, "provider_name"),
                     ("planned_values", "root_module", "resources", 0, "provider_name"),
                     ("prior_state", "values", "root_module", "resources", 0, "provider_name")):
            candidate = copy.deepcopy(plan)
            set_path(candidate, path, "tailscale")
            self.assertRejected(inputs(encoded(candidate)))

    def test_complete_resource_fields_and_malformed_metadata(self):
        plan = json.loads(encoded(fixture_plan()))
        paths = [("resource_changes", 0), ("resource_changes", 0, "change"),
                 ("resource_changes", 0, "change", "before"), ("resource_changes", 0, "change", "after"),
                 ("resource_changes", 0, "change", "before", "input"),
                 ("planned_values", "root_module", "resources", 0),
                 ("prior_state", "values", "root_module", "resources", 0)]
        for path in paths:
            item = plan
            for key in path:
                item = item[key]
            for field in item:
                with self.subTest(path=path, missing=field):
                    candidate = copy.deepcopy(plan); target = candidate
                    for key in path:
                        target = target[key]
                    del target[field]
                    self.assertRejected(inputs(encoded(candidate)))
        for path, value in [(("configuration", "root_module", "variables"), None),
                            (("configuration", "provider_config"), []),
                            (("configuration", "root_module", "resources", 0, "count_expression"), {"references": [True]}),
                            (("configuration", "root_module", "resources", 0, "expressions", "input"), {"references": ["module.secret"]})]:
            candidate = copy.deepcopy(plan); set_path(candidate, path, value)
            self.assertRejected(inputs(encoded(candidate)))

    def test_policy_structures(self):
        mutations = [(("grants",), []), (("grants", 0, "src"), "*"),
                     (("grants", 0, "ip"), ["tcp:65536"]), (("grants", 0, "ip"), [True]),
                     (("ssh", 0, "action"), "bogus"), (("ssh", 0, "users"), ["fixture", "fixture"]),
                     (("tests", 0, "accept"), ["tag:fixture:0"]), (("tests", 0, "proto"), False),
                     (("tests", 0, "deny"), ["tag:fixture:22"]), (("sshTests", 0, "dst"), "tag:fixture"),
                     (("sshTests", 0, "src"), None), (("tagOwners",), []), (("acls",), [])]
        for path, replacement in mutations:
            with self.subTest(path=path):
                policy = copy.deepcopy(POLICY); set_path(policy, path, replacement)
                data = inputs(); data["expected_policy"] = encoded(policy)
                self.assertEqual(self.assertRejected(data)["errors"], ["policy-structure"])
        for section in POLICY:
            policy = copy.deepcopy(POLICY); del policy[section]
            data = inputs(); data["expected_policy"] = encoded(policy)
            self.assertEqual(self.assertRejected(data)["errors"], ["policy-structure"])

    def test_policy_substitution(self):
        policy = copy.deepcopy(POLICY); policy["ssh"][0]["users"] = ["different"]
        for name in ("expected_policy", "live_before", "live_after"):
            data = inputs(); data[name] = encoded(policy)
            self.assertRejected(data)
        # All bodies and plan JSON changed, but embedded original-string hash stale.
        plan = json.loads(encoded(fixture_plan()))
        for value in (plan["resource_changes"][0]["change"]["before"], plan["resource_changes"][0]["change"]["after"],
                      plan["planned_values"]["root_module"]["resources"][0]["values"],
                      plan["prior_state"]["values"]["root_module"]["resources"][0]["values"]):
            value["input"]["policy_json"] += "\n"
            value["output"]["policy_json"] += "\n"
        self.assertEqual(self.assertRejected(inputs(encoded(plan)))["errors"], ["embedded-policy-hash"])

    def test_headers_and_etags(self):
        body = inputs()["live_before"]
        variants = [b"", b"HTTP/2 200\nETag: \"x\"\n\n", header(body).replace(b"200", b"302", 1),
                    header(body).replace(b"200", b"500", 1), header(body) + header(body),
                    b"HTTP/1.1 100 Continue\r\n\r\n" + header(body),
                    header(body).replace(b"Content-Type", b" Content-Type"),
                    header(body).replace(b"application/json", b"text/html"),
                    header(body).replace(str(len(body)).encode(), b"0"),
                    header(body).replace(b"\r\n\r\n", b"\r\nLocation: /hidden\r\n\r\n"),
                    header(body).replace(b"\r\n\r\n", b"\r\netag: \"fixture-etag\"\r\n\r\n"),
                    header(body).replace(b"\r\n\r\n", b"\r\nX-Test: a\r\nx-test: b\r\n\r\n"),
                    header(body).replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
                    header(body).replace(b"\r\n\r\n", b"\r\nContent-Encoding: gzip\r\n\r\n"),
                    header(body).replace(b"\r\n\r\n", b"\r\nX-Test: secret\x00\r\n\r\n")]
        variants.extend(header(body, etag) for etag in ('W/"weak"', 'bare', '""', '"a", "b"', '"bad\t"', '"other"'))
        for name in ("headers_before", "headers_after"):
            for raw in variants:
                with self.subTest(name=name, raw=raw):
                    data = inputs(); data[name] = raw
                    self.assertRejected(data)
        for version in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK", b"HTTP/2 200"):
            data = inputs()
            for name in ("headers_before", "headers_after"):
                data[name] = header(body).replace(b"HTTP/2 200", version)
            self.assertTrue(verify(data)["content_consistent"])

    def test_strict_json_bounds_and_redaction(self):
        invalid = [b'{"secret":1,"secret":2}', b'{"secret":NaN}', b'{"secret":Infinity}',
                   b'{"secret":1e999}', b'{"secret":1.0}', b'{"secret":9223372036854775808}',
                   b'{"secret":"\\ud800"}', b'\xff', b'\xef\xbb\xbf{}', b'{} trailing', b'null', b'true',
                   b'[' * 1000 + b']' * 1000]
        for name in ("plan", "expected_policy", "live_before", "live_after"):
            for raw in invalid:
                data = inputs(); data[name] = raw
                output = self.assertRejected(data)
                self.assertNotIn(b"secret", diag.canonical(output))
        for key, limit in diag.LIMITS.items():
            data = inputs(); data[key] = b" " * (limit + 1)
            self.assertEqual(self.assertRejected(data)["errors"], ["input-bound"])
        with self.assertRaises(diag.Invalid):
            diag.Budget().parse(b'[' + b'0,' * diag.MAX_NODES + b'0]', 1024 * 1024)
        with self.assertRaises(diag.Invalid):
            diag.Budget().parse(b'[' * 49 + b'0' + b']' * 49, 1024)
        budget = diag.Budget(); budget.nodes = diag.MAX_NODES
        with self.assertRaises(diag.Invalid):
            budget.parse(b'{}', 1024)


class CliFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tailscale-diagnostic-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.data = inputs()
        self.paths = {}
        for key, raw in self.data.items():
            path = self.directory / key
            path.write_bytes(raw); path.chmod(0o600)
            self.paths[key] = path

    def command(self, script=SCRIPT):
        args = [str(script)]
        for key, path in self.paths.items():
            args += ["--" + key.replace("_", "-"), str(path)]
        return args + ["--expected-sha256", diag.sha(self.data["expected_policy"])]

    def cli(self, args=None, env=None):
        process = subprocess.run(args or self.command(), cwd=self.directory, env=env,
                                 capture_output=True, timeout=20)
        self.assertEqual(process.stderr, b"")
        output = json.loads(process.stdout)
        self.assertEqual(process.stdout, diag.canonical(output))
        self.assertLess(len(process.stdout), 4096)
        self.assertEqual(process.returncode, 0 if output["content_consistent"] else 1)
        self.assertFalse(output["authorized"])
        self.assertFalse(output["admission_eligible"])
        self.assertEqual(output["blockers"], diag.BLOCKERS)
        self.assertNotIn(str(self.directory).encode(), process.stdout)
        return output

    def snapshot(self):
        return {str(p.relative_to(self.directory)): (p.lstat().st_mode, p.lstat().st_size,
                    p.lstat().st_mtime_ns, p.lstat().st_ctime_ns, p.read_bytes() if p.is_file() and not p.is_symlink() else None)
                for p in self.directory.rglob("*")}


class FileAndCliTests(CliFixture, unittest.TestCase):
    def test_real_cli_to_unchanged_strict_v1_consumer(self):
        before = self.snapshot()
        output = self.cli()
        self.assertTrue(output["content_consistent"], output)
        self.assertEqual(before, self.snapshot())
        protected = load(SCRIPT.with_name("protected_execution.py"))
        with patch.dict(sys.modules, {"protected_execution": protected}):
            capability = load(SCRIPT.with_name("proxmox-controller-observer-capability.py"))
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        for flipped in (False, True):
            candidate = copy.deepcopy(output)
            candidate.update(authorized=flipped, admission_eligible=flipped)
            with self.assertRaises(ValueError):
                capability.validate_access(candidate, diag.canonical(candidate), "a" * 40, "b" * 64, "c" * 64, now)

    def test_cli_argument_errors_and_nonisolated_invocation(self):
        for args in ([str(SCRIPT)], self.command() + ["--private-secret-path"],
                     self.command()[:-2] + ["--plan", "/secret"],
                     ["/usr/bin/python3", "-B", *self.command()],
                     ["/usr/bin/python3", "-I", *self.command()]):
            self.assertFalse(self.cli(args)["content_consistent"])
        self.assertTrue(self.cli(["/usr/bin/python3", "-I", "-B", "-S", *self.command()])["content_consistent"])

    def test_file_attacks_without_mutation(self):
        original = self.paths["plan"]
        attacks = []
        link = self.directory / "symlink"; link.symlink_to(original); attacks.append(link)
        hard = self.directory / "hard"; os.link(original, hard); attacks.append(hard)
        fifo = self.directory / "fifo"; os.mkfifo(fifo, 0o600); attacks.append(fifo)
        attacks.append(self.directory)
        missing = self.directory / "missing"; attacks.append(missing)
        unsafe = self.directory / "unsafe"; unsafe.write_bytes(self.data["plan"]); unsafe.chmod(0o644); attacks.append(unsafe)
        big = self.directory / "big"; big.write_bytes(b" " * (diag.LIMITS["plan"] + 1)); big.chmod(0o600); attacks.append(big)
        for path in attacks:
            with self.subTest(path=path.name):
                self.paths["plan"] = path
                before = self.snapshot()
                self.assertFalse(self.cli()["content_consistent"])
                self.assertEqual(before, self.snapshot())
        hard.unlink()  # Test fixture cleanup, never diagnostic behavior.
        self.paths["plan"] = original
        directory = self.directory / "unsafe-parent"; directory.mkdir(mode=0o777); directory.chmod(0o777)
        path = directory / "plan"; path.write_bytes(self.data["plan"]); path.chmod(0o600)
        self.paths["plan"] = path
        self.assertFalse(self.cli()["content_consistent"])
        alias = self.directory / "alias"; alias.symlink_to(directory, target_is_directory=True)
        self.paths["plan"] = alias / "plan"
        self.assertFalse(self.cli()["content_consistent"])
        self.paths["plan"] = original
        original.chmod(0o400)
        self.assertTrue(self.cli()["content_consistent"])

    def test_retained_reads_detect_content_inode_and_ancestor_replacement(self):
        for attack in ("content", "inode", "ancestor", "hardlink", "mode"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory(dir=self.directory) as temp:
                directory = Path(temp); path = directory / "file"; path.write_bytes(b"one"); path.chmod(0o600)
                reads = diag.PrivateReads()
                try:
                    self.assertEqual(reads.read(str(path), 100), b"one")
                    if attack == "content":
                        path.write_bytes(b"two")
                    elif attack == "inode":
                        path.rename(directory / "old"); path.write_bytes(b"one"); path.chmod(0o600)
                    elif attack == "ancestor":
                        directory.rename(str(directory) + "-old"); directory.mkdir(mode=0o700)
                    elif attack == "hardlink":
                        os.link(path, directory / "hard")
                    else:
                        path.chmod(0o644)
                    with self.assertRaises((diag.Invalid, OSError)):
                        reads.check()
                finally:
                    reads.close()
        # Replacement during a descriptor read is refused, not just later polling.
        path = self.paths["plan"]; real_read = os.read; replaced = False
        def replace(fd, count):
            nonlocal replaced
            raw = real_read(fd, count)
            if raw and not replaced:
                replaced = True
                path.rename(self.directory / "old-plan")
                path.write_bytes(self.data["plan"]); path.chmod(0o600)
            return raw
        reads = diag.PrivateReads()
        try:
            with patch.object(diag.os, "read", side_effect=replace), self.assertRaises(diag.Invalid):
                reads.read(str(path), diag.LIMITS["plan"])
        finally:
            reads.close()

    def copy_sources(self):
        directory = self.directory / "source"; directory.mkdir(mode=0o700)
        for source in (SCRIPT, HELPER):
            target = directory / source.name
            target.write_bytes(source.read_bytes()); target.chmod(0o755 if source == SCRIPT else 0o644)
        return directory / SCRIPT.name

    def test_helper_source_replacement_and_retained_source_rechecks(self):
        script = self.copy_sources(); helper = script.with_name(HELPER.name)
        helper.write_bytes(b'raise RuntimeError("private-source-secret")\n')
        output = self.cli(self.command(script))
        self.assertEqual(output["errors"], ["helper-source-mismatch"])
        helper.write_bytes(HELPER.read_bytes())
        for target in (script, helper):
            reads = diag.PrivateReads()
            try:
                with patch.object(diag, "__file__", str(script)):
                    diag.load_helper(reads)
                target.rename(target.with_suffix(".old"))
                target.write_bytes(target.with_suffix(".old").read_bytes()); target.chmod(0o755 if target == script else 0o644)
                with self.assertRaises(diag.Invalid):
                    reads.check()
            finally:
                reads.close()

    def test_unchecked_hash_bytecode_and_ambient_python_injection(self):
        script = self.copy_sources(); helper = script.with_name(HELPER.name)
        poison = self.directory / "poison.py"
        poison.write_text('raise RuntimeError("PRIVATE-AMBIENT-INJECTION")\n')
        cache = helper.parent / "__pycache__"; cache.mkdir()
        py_compile.compile(str(poison), cfile=str(cache / ("tailscale-policy." + sys.implementation.cache_tag + ".pyc")),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH, doraise=True)
        # A sourceless adjacent cache must not be consulted either.
        shutil.copyfile(next(cache.iterdir()), helper.with_suffix(".pyc"))
        for name in ("sitecustomize.py", "usercustomize.py", "json.py", "hashlib.py"):
            (self.directory / name).write_bytes(poison.read_bytes())
            (helper.parent / name).write_bytes(poison.read_bytes())
        env = dict(os.environ, PYTHONPATH=str(self.directory), PYTHONHOME=str(self.directory),
                   PYTHONSTARTUP=str(poison), PYTHONUSERBASE=str(self.directory))
        before = self.snapshot()
        self.assertTrue(self.cli(self.command(script), env=env)["content_consistent"])
        self.assertEqual(before, self.snapshot())
        # Pinned SOURCE is still mandatory even with a cache claiming success.
        helper.unlink()
        self.assertFalse(self.cli(self.command(script), env=env)["content_consistent"])


class LocalOpenTofuTests(CliFixture, unittest.TestCase):
    def test_local_builtin_decoded_noop(self):
        tofu = shutil.which("tofu")
        if tofu is None:
            self.skipTest("no existing local OpenTofu; synthetic parser cases are not binary provenance")
        sandbox = Path("/usr/bin/sandbox-exec")
        if sys.platform != "darwin" or not sandbox.is_file():
            self.skipTest("native fixture requires the existing macOS network-denial sandbox")
        isolated_tofu = [str(sandbox), "-p", "(version 1) (allow default) (deny network*)", tofu]
        directory = self.directory / "builtin"; directory.mkdir(mode=0o700)
        config = '''variable "tailscale_enable_management" {
  type = bool
  default = true
}
locals {
  policy = jsondecode(POLICY_LITERAL)
  policy_json = jsonencode(local.policy)
}
resource "terraform_data" "tailscale_policy" {
  count = var.tailscale_enable_management ? 1 : 0
  input = {
    policy_json = local.policy_json
    policy_sha256 = sha256(local.policy_json)
  }
  lifecycle { prevent_destroy = true }
}
'''.replace("POLICY_LITERAL", json.dumps(encoded(POLICY).decode()))
        # Tofu jsonencode sorts object keys; hand-built synthetic state is NOT apply/import.
        raw = json.dumps(POLICY, separators=(",", ":"), sort_keys=True).encode()
        input_value = {"policy_json": raw.decode(), "policy_sha256": diag.sha(raw)}
        value_type = ["object", {"policy_json": "string", "policy_sha256": "string"}]
        state = {"version": 4, "terraform_version": "1.12.5", "serial": 1,
                 "lineage": "00000000-0000-0000-0000-000000000001", "outputs": {}, "resources": [{
                     "mode": "managed", "type": "terraform_data", "name": "tailscale_policy",
                     "provider": 'provider["terraform.io/builtin/terraform"]', "instances": [{
                         "index_key": 0, "schema_version": 0, "attributes": {
                             "id": "synthetic-id", "input": {"value": input_value, "type": value_type},
                             "output": {"value": input_value, "type": value_type}, "triggers_replace": None},
                         "sensitive_attributes": []}]}]}
        (directory / "main.tf").write_text(config)
        (directory / "terraform.tfstate").write_bytes(encoded(state))
        original_state = (directory / "terraform.tfstate").read_bytes()
        rc = directory / "empty.rc"; rc.write_text("disable_checkpoint = true\nprovider_installation {\n filesystem_mirror { path = \"" + str(directory / "no-providers") + "\" }\n}\n")
        (directory / "no-providers").mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(directory), "TF_IN_AUTOMATION": "1",
               "CHECKPOINT_DISABLE": "1", "TF_CLI_CONFIG_FILE": str(rc)}
        commands = [("init", "-backend=false", "-input=false", "-no-color"),
                    ("plan", "-refresh=false", "-lock=false", "-input=false", "-no-color", "-out=fixture.plan"),
                    ("show", "-json", "fixture.plan")]
        for command in commands:
            process = subprocess.run([*isolated_tofu, *command], cwd=directory, env=env, capture_output=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual((directory / "terraform.tfstate").read_bytes(), original_state)
        decoded = process.stdout
        self.paths["plan"].write_bytes(decoded)
        output = self.cli()
        self.assertTrue(output["content_consistent"], output)
        self.assertEqual(output["origin"], "unqualified-import")
        self.assertIn("binary-to-json-linkage-unproven", output["blockers"])
        self.assertEqual(output["inputs"]["plan"]["sha256"], diag.sha(decoded))
        print("local builtin-only OpenTofu decoded fixture: " + json.loads(decoded)["terraform_version"] +
              "; synthetic state, no apply/import/backend/provider download; NOT provenance qualification")



if __name__ == "__main__":
    unittest.main()
