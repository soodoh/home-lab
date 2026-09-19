#!/usr/bin/env python3
"""Contract-bound production dependency admission; synthetic only, no host access."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / path))
    spec = importlib.util.spec_from_loader(name, loader)
    value = importlib.util.module_from_spec(spec)
    loader.exec_module(value)
    return value


fixtures = load("transaction_fixtures", "scripts/controller/test-debian-lifecycle-transactions.py")
controller = fixtures.module
host = load("dependency_host", "ansible/roles/debian_lifecycle_transaction/files/debian-lifecycle-host-transaction")
GRAPH = deepcopy(fixtures.actual_policy["transaction"]["production_systemd_dependencies"])
UNITS = fixtures.actual_policy["transaction"]["production_units"]


def hostile_graphs():
    yield "empty graph", {}
    yield "empty nodes", {unit: {} for unit in GRAPH}
    yield "empty properties", {unit: {"Requires": [], "After": []} for unit in GRAPH}
    yield "legacy union", {unit: sorted(set(p["Requires"] + p["After"])) for unit, p in GRAPH.items()}
    yield "null", None
    for unit in GRAPH:
        value = deepcopy(GRAPH); del value[unit]
        yield f"missing unit {unit}", value
        for prop in ("Requires", "After"):
            value = deepcopy(GRAPH); del value[unit][prop]
            yield f"missing property {unit} {prop}", value
            for edge in GRAPH[unit][prop]:
                value = deepcopy(GRAPH); value[unit][prop].remove(edge)
                yield f"missing edge {unit} {prop} {edge}", value
    value = deepcopy(GRAPH)
    timer = "home-lab-restic-daily.timer"
    value[timer]["Requires"], value[timer]["After"] = value[timer]["After"], value[timer]["Requires"]
    yield "swapped timer property", value
    value = deepcopy(GRAPH); value["docker.service"]["After"].append("docker.service")
    yield "unreviewed cycle", value


def shown(properties):
    # Match systemctl's quoted escaped mount unit output, not a shell command.
    return "".join(f"{prop}=" + " ".join(json.dumps(edge) if "\\" in edge else edge for edge in edges) + "\n" for prop, edges in properties.items())


class ProductionDependencies(unittest.TestCase):
    def setUp(self):
        _, self.request, self.observation = next(entry for entry in fixtures.cases(fixtures.NOW) if entry[0] == "production-activation")
        self.policy = controller.production_dependency_policy()
        self.plan = {
            "bindings": {"contract_sha256": self.policy["contract_sha256"], "production_dependency_policy_sha256": host.sha(host.canonical(self.policy))},
            "request": self.request,
            "precondition": self.observation,
        }

    def test_unchanged_reinstallation_reloads_after_interrupted_reload(self):
        tasks = json.loads(subprocess.check_output([
            "node", "-e", "const fs=require('fs'),y=require('js-yaml');process.stdout.write(JSON.stringify(y.load(fs.readFileSync(process.argv[1],'utf8'))))",
            str(ROOT / "ansible/roles/debian_lifecycle_capability/tasks/main.yml"),
        ], cwd=ROOT, text=True))
        task = next(t for t in tasks if t["name"] == "Reload dependency declarations without activating or restarting units")
        self.assertEqual(task["ansible.builtin.systemd_service"], {"daemon_reload": True})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            counter = root / "reload-count"
            program = "from pathlib import Path;import sys;p=Path(sys.argv[1]);n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n));sys.exit(1 if n==1 else 0)"
            playbook = root / "retry.yml"
            # Execute the real role condition, replacing only the systemd endpoint
            # with a synthetic reload that fails once after declarations exist.
            playbook.write_text(json.dumps([{
                "name": "Synthetic interrupted declaration reload", "hosts": "localhost", "gather_facts": False,
                "vars": {"debian_lifecycle_capability_dependencies": {"changed": False}},
                "tasks": [{"name": task["name"], "when": task["when"],
                           "ansible.builtin.command": {"argv": [sys.executable, "-c", program, str(counter)]},
                           "changed_when": True}],
            }]))
            command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)]
            env = {**os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg")}
            first = subprocess.run(command, env=env, text=True, capture_output=True)
            self.assertNotEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertEqual(counter.read_text(), "1")
            second = subprocess.run(command, env=env, text=True, capture_output=True)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertEqual(counter.read_text(), "2")
            check = subprocess.run(command + ["--check"], env=env, text=True, capture_output=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            self.assertEqual(counter.read_text(), "2")

    def test_contract_schema_and_production_order(self):
        schema = json.loads((ROOT / "infrastructure/contract/schema.json").read_bytes())
        declaration = schema["properties"]["debian"]["properties"]["transaction"]
        self.assertEqual(declaration["properties"]["production_systemd_dependencies"]["const"], GRAPH)
        self.assertIn("production_systemd_dependencies", declaration["required"])
        self.assertEqual(UNITS, list(host.PRODUCTION_UNITS))
        for unit in UNITS[:2]:
            for prop in ("Requires", "After"):
                self.assertTrue({"home-lab-production-guard.service", "mnt-games.mount", "mnt-storage.mount", r"srv-home\x2dlab\x2dstate.mount"}.issubset(GRAPH[unit][prop]))
        self.assertIn("docker.service", GRAPH[UNITS[1]]["Requires"])
        self.assertIn("docker.service", GRAPH[UNITS[1]]["After"])
        for timer in UNITS[2:]:
            self.assertEqual(GRAPH[timer], {"Requires": [], "After": ["home-lab-compose.service"]})
        for index, unit in enumerate(UNITS):
            for edge in GRAPH[unit]["After"]:
                if edge in UNITS:
                    self.assertLess(UNITS.index(edge), index)

    def test_schema_rejects_missing_or_weakened_contract_graphs(self):
        script = """
const fs = require('fs'), yaml = require('js-yaml'), Ajv = require('ajv/dist/2020');
const contract = yaml.load(fs.readFileSync('infrastructure/contract/home-lab.yml', 'utf8'));
const validate = new Ajv({strict:true, allErrors:true}).compile(JSON.parse(fs.readFileSync('infrastructure/contract/schema.json')));
if (!validate(contract)) throw Error(JSON.stringify(validate.errors));
for (const graph of JSON.parse(fs.readFileSync(0, 'utf8'))) {
  const candidate = structuredClone(contract);
  candidate.debian.transaction.production_systemd_dependencies = graph;
  if (validate(candidate)) throw Error('weakened graph accepted');
}
delete contract.debian.transaction.production_systemd_dependencies;
if (validate(contract)) throw Error('missing graph accepted');
"""
        subprocess.run(["node", "-e", script], input=json.dumps([graph for _, graph in hostile_graphs()]), text=True, cwd=ROOT, check=True, capture_output=True)

    def test_matching_weakened_request_and_observation_are_blocked(self):
        for label, graph in hostile_graphs():
            with self.subTest(label=label):
                request, observation = deepcopy(self.request), deepcopy(self.observation)
                request["parameters"]["systemd_dependencies"] = graph
                observation["production"]["systemd_dependencies"] = deepcopy(graph)
                blockers = controller.validate_request("production-activation", request, observation, fixtures.NOW)
                self.assertIn("contract-systemd-dependencies-drift", blockers)

    def test_weakened_saved_plan_cannot_reach_mutation_even_with_forged_blockers(self):
        with tempfile.TemporaryDirectory(prefix=".dependency-test-", dir=ROOT) as raw:
            root = Path(raw).resolve(); output = root / "plans"; output.mkdir(mode=0o700)
            evidence = fixtures.evidence_for("production-activation", self.request, root)
            self.observation["production"]["restic_recovery_receipt_sha256"] = self.request["parameters"]["restic_recovery_receipt_sha256"]
            self.request["parameters"]["systemd_dependencies"] = {}
            self.observation["production"]["systemd_dependencies"] = {}
            request, observation = root / "request.json", root / "observation.json"
            fixtures.write(request, self.request); fixtures.write(observation, self.observation)
            _, _, plan = controller.make_plan("production-activation", request, observation, output, fixtures.NOW, fixtures.COMMIT, evidence)
            plan["blockers"] = ["saved-reviewed-plan-required", "separate-exact-authorization-required"]
            raw_plan = fixtures.canonical(plan)
            path = output / f"production-activation-{controller.sha(raw_plan)}.json"
            fixtures.write(path, raw_plan)
            with patch.object(controller, "run_controlled", side_effect=AssertionError("mutation reached")), patch.object(controller, "acquire_transfer_lock", side_effect=AssertionError("lock mutation reached")):
                with self.assertRaisesRegex(SystemExit, "precondition or blockers"):
                    controller.apply("production-activation", path, observation, None, fixtures.NOW, fixtures.COMMIT, evidence)

    def test_observation_requires_each_property_but_allows_systemd_defaults(self):
        current = deepcopy(GRAPH)
        current["docker.service"]["Requires"].append("sysinit.target")
        self.assertTrue(controller.dependencies_satisfied(GRAPH, current))
        for label, graph in hostile_graphs():
            with self.subTest(label=label):
                self.assertFalse(controller.dependencies_satisfied(GRAPH, graph))

    def test_host_independently_rejects_request_before_commands_or_mutation(self):
        for label, graph in hostile_graphs():
            with self.subTest(label=label):
                plan = deepcopy(self.plan); plan["request"]["parameters"]["systemd_dependencies"] = graph
                plan["precondition"]["production"]["systemd_dependencies"] = deepcopy(graph)
                with patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", return_value=host.canonical(self.policy)), patch.object(host, "run", side_effect=AssertionError("command reached")), patch.object(host, "require_regular", side_effect=AssertionError("production state reached")):
                    with self.assertRaisesRegex(SystemExit, "request dependency graph"):
                        host.production(plan, "a" * 64)

    def test_host_main_rejects_weakened_graph_before_creating_host_lock(self):
        plan = deepcopy(self.plan)
        now = datetime.now(timezone.utc)
        plan.update(operation="production-activation", profile="recovery", authorized=False, automatic_apply=False,
                    blockers=["saved-reviewed-plan-required", "separate-exact-authorization-required"],
                    created_at=now.isoformat(), expires_at=(now + timedelta(minutes=10)).isoformat())
        plan["request"]["parameters"]["systemd_dependencies"] = {}
        digest = host.sha(host.canonical(plan))
        argv = ["executor", "production-activation", digest, f"apply-debian-production-activation-{digest}"]
        with patch.object(sys, "argv", argv), patch.object(host.signal, "signal"), patch.object(host.os, "read", return_value=host.canonical({"plan": plan})), patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", return_value=host.canonical(self.policy)), patch.object(host, "acquire_host_lock", side_effect=AssertionError("host lock mutation reached")):
            with self.assertRaisesRegex(SystemExit, "request dependency graph"):
                host.main()

    def test_installed_policy_binding_and_legacy_versions_fail_closed(self):
        for field in ("contract_sha256", "production_dependency_policy_sha256"):
            plan = deepcopy(self.plan); plan["bindings"][field] = "0" * 64
            with patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", return_value=host.canonical(self.policy)):
                with self.assertRaisesRegex(SystemExit, "policy binding"):
                    host.production_dependency_policy(plan)
        for key, version in (("request", "request"), ("precondition", "observation")):
            plan = deepcopy(self.plan); plan[key]["format"] = f"home-lab-debian-lifecycle-{version}-v1"
            with patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", return_value=host.canonical(self.policy)):
                with self.assertRaisesRegex(SystemExit, "request dependency graph"):
                    host.production_dependency_policy(plan)
            with self.assertRaises(SystemExit):
                controller.validate_request("production-activation", plan["request"], plan["precondition"], fixtures.NOW)
        with patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                host.production_dependency_policy(self.plan)

    def test_live_requires_and_after_are_separate_before_mutation(self):
        for label, graph in hostile_graphs():
            if not isinstance(graph, dict) or set(graph) != set(GRAPH):
                continue
            def observe(argv, **kwargs):
                properties = graph[argv[2]]
                text = shown(properties) if isinstance(properties, dict) else "dep.mount\n"
                return subprocess.CompletedProcess(argv, 0, text, "")
            with self.subTest(label=label), patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", return_value=host.canonical(self.policy)), patch.object(host, "run", side_effect=observe), patch.object(host, "require_regular", side_effect=AssertionError("production state reached")):
                with self.assertRaises(SystemExit):
                    host.production(self.plan, "a" * 64)

    def test_systemctl_escaped_mounts_named_properties_and_failures(self):
        calls = []
        def observe(argv, **kwargs):
            calls.append(argv)
            properties = deepcopy(GRAPH[argv[2]])
            properties["Requires"].append("sysinit.target")
            properties["After"].append("sysinit.target")
            return subprocess.CompletedProcess(argv, 0, shown(properties), "")
        with patch.object(host, "run", side_effect=observe):
            host.verify_production_dependencies(self.policy)
        self.assertEqual([argv[2] for argv in calls], UNITS)
        self.assertTrue(all(argv[-1] == "--property=Requires,After" for argv in calls))
        mount = r"srv-home\x2dlab\x2dstate.mount"
        self.assertEqual(host.systemd_dependency_properties(f"Requires={mount}\nAfter={json.dumps(mount)}\n"), {"Requires": {mount}, "After": {mount}})
        for text in ('Requires=\n', 'Requires=\nRequires=\n', 'Requires=\nAfter=\nBogus=\n', 'Requires="unterminated\nAfter=\n', 'Requires="unit.service"suffix\nAfter=\n', 'Requires=unit.service unit.service\nAfter=\n'):
            with self.subTest(text=text), self.assertRaises(SystemExit):
                host.systemd_dependency_properties(text)
        with patch.object(host, "run", return_value=subprocess.CompletedProcess([], 1, shown(GRAPH[UNITS[0]]), "")):
            with self.assertRaisesRegex(SystemExit, "observation failed"):
                host.verify_production_dependencies(self.policy)

    def test_success_starts_and_checks_all_units_in_contract_order(self):
        with tempfile.TemporaryDirectory(prefix=".dependency-test-", dir=ROOT) as raw:
            root = Path(raw)
            token, marker = root / "token", root / "marker"
            params = self.plan["request"]["parameters"]
            token.write_text(f"plan_sha256={params['storage_plan_sha256']}\n")
            marker.write_bytes(host.canonical({"state": "recovery"}))
            params["lifecycle_marker_sha256"] = host.sha(marker.read_bytes())
            receipts = fixtures.evidence_for("production-activation", self.request, root)
            artifacts = {str(host.PRODUCTION_DEPENDENCY_POLICY): host.canonical(self.policy)}
            for path_key, hash_key in (("compose_artifact_path", "compose_artifact_sha256"), ("compose_image_lock_path", "compose_image_lock_sha256"), ("root_environment_path", "root_environment_sha256"), ("restic_recovery_receipt_path", "restic_recovery_receipt_sha256")):
                content = receipts[0].read_bytes() if path_key == "restic_recovery_receipt_path" else b"synthetic"
                artifacts[params[path_key]] = content
                params[hash_key] = host.sha(content)
            self.plan["bindings"]["authority_producer_sha256"] = controller.sha(controller.AUTHORITY_PRODUCER.read_bytes())
            self.plan["base_commit"] = fixtures.COMMIT
            commands = []
            def run(argv, **kwargs):
                commands.append(argv)
                text = ""
                if "age-keygen" in argv[0]:
                    text = params["identity_recipient"]
                elif argv[:2] == ["/usr/bin/tailscale", "status"]:
                    text = json.dumps({"BackendState": "Running", "Self": {"HostName": params["tailscale_hostname"], "Tags": params["tailscale_tags"]}})
                elif argv[:2] == ["/usr/bin/systemctl", "show"]:
                    text = shown(GRAPH[argv[2]]) if argv[-1] == "--property=Requires,After" else "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                return subprocess.CompletedProcess(argv, 0, text, "")
            with patch.object(host, "safe_directory"), patch.object(host, "read_root_regular", side_effect=lambda path, *args: artifacts[str(path)]), patch.object(host, "require_regular", side_effect=lambda path, *args, **kwargs: os.lstat(path) if Path(path) == marker else None), patch.object(host, "verify_mount"), patch.object(host, "STORAGE_TOKEN", token), patch.object(host, "LIFECYCLE_MARKER", marker), patch.object(host.os, "fchown"), patch.object(host, "run", side_effect=run):
                host.production(self.plan, "a" * 64)
            starts = [argv[2] for argv in commands if argv[:2] == ["/usr/bin/systemctl", "start"]]
            self.assertEqual(starts, UNITS)
            for unit in UNITS:
                start = commands.index(["/usr/bin/systemctl", "start", unit])
                self.assertEqual(commands[start + 1], ["/usr/bin/systemctl", "is-active", "--quiet", unit])
            self.assertEqual(json.loads(marker.read_bytes())["state"], "production")


if __name__ == "__main__":
    unittest.main()
