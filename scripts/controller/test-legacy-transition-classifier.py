#!/usr/bin/env python3
"""Synthetic-only causal tests; no helpers, host fixtures or production inputs."""
import ast
import builtins
import copy
import io
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

SOURCE_PATH = Path(__file__).with_name("legacy-transition-classifier.py")
SOURCE = SOURCE_PATH.read_text()
CLASSIFIER = {}
exec(compile(SOURCE, str(SOURCE_PATH), "exec"), CLASSIFIER)
classify = CLASSIFIER["classify"]

# Independent oracle: do not derive fixtures/expectations from classifier tables.
ROLE_PATHS = (
    ("ordinary-observer", "/usr/local/libexec/home-lab/proxmox-observer"),
    ("package-observer", "/usr/local/libexec/home-lab/proxmox-package-candidate-observer"),
    ("plan-transport", "/usr/local/libexec/home-lab/proxmox-ansible-plan-transport"),
    ("deploy-activator", "/usr/local/libexec/home-lab/proxmox-ansible-deploy-activator"),
    ("ansible-plan-sudo", "/etc/sudoers.d/ansible-plan"),
    ("private-preparer", "/usr/local/libexec/home-lab/proxmox-private-preparer"),
    ("firewall-helper", "/usr/local/libexec/home-lab/proxmox-firewall-transaction"),
    ("firewall-transport", "/usr/local/libexec/home-lab/proxmox-firewall-transport"),
    ("firewall-sudo", "/etc/sudoers.d/firewall-apply"),
    ("protected-collector", "/usr/local/libexec/home-lab/proxmox-protected-collector"),
    ("controller-observer", "/usr/local/libexec/home-lab/proxmox-controller-observer"),
)
BLOCKERS = [
    "complete-real-audit-and-closed-support-catalog-unqualified",
    "original-and-recovery-authority-unverified",
    "origin-host-console-and-runtime-unqualified",
    "evidence-specific-freshness-unqualified",
    "source-profile-approval-and-compatibility-unqualified",
    "asynchronous-writer-coordination-unqualified",
    "crash-durable-ownership-and-publication-identity-unverified",
    "original-terminal-audit-authenticity-unverified",
]
PHASES = {
    "prepared": ("before", "rollback-exact"),
    "candidate": ("candidate", "rollback-exact"),
    "rollback-restored": ("restored_before", "rollback-exact"),
    "committed": ("candidate", "cleanup-committed"),
    "rolled-back": ("restored_before", "cleanup-rolled-back"),
}


def obj(name, content):
    return {"object_ref": "synthetic:" + name, "content_ref": "synthetic:" + content}


def fixture(state="candidate", noop=False):
    profile, action = PHASES[state]
    rows = []
    for index, (role, path) in enumerate(ROLE_PATHS):
        before = obj(role + "-before", role + "-old")
        candidate = obj(role + "-candidate", role + "-new")
        restored = obj(role + "-restored", role + "-old")
        change = "replace"
        if index >= 9:
            change, before, restored = "new-output", None, None
        elif index >= 5 or noop:
            change = "preserve" if index >= 5 else "noop"
            candidate, restored = copy.deepcopy(before), copy.deepcopy(before)
        rows.append(dict(role=role, path=path, change=change, before=before,
                         candidate=candidate, restored_before=restored))
    audit = "synthetic:original-terminal-audit" if state in ("committed", "rolled-back") else None
    return {
        "format": "synthetic-only-legacy-transition-assertions-v0",
        "original": {"reference": "synthetic:original", "owner_ref": "synthetic:owner",
                     "state": state, "generation": 7, "terminal_audit_ref": audit, "roles": rows},
        "recovery": {"reference": "synthetic:recovery", "original_ref": "synthetic:original",
                     "start_state": state, "start_generation": 7, "action": action},
        "current": {"original_ref": "synthetic:original", "owner_ref": "synthetic:owner",
                    "state": state, "generation": 7, "terminal_audit_ref": audit,
                    "roles": [{"role": row["role"], "path": row["path"],
                               "object": copy.deepcopy(row[profile])} for row in rows]},
    }


class LegacyTransitionClassifierTests(unittest.TestCase):
    def result(self, value, code="synthetic-consistency-only", function=classify):
        result = function(value)
        self.assertEqual(result, {
            "format": "synthetic-only-legacy-transition-classification-v0",
            "status": "well-formed-for-further-qualification" if code == "synthetic-consistency-only" else "refused",
            "classification": code, "authorized": False, "admission_eligible": False,
            "blockers": BLOCKERS,
        })
        self.assertIs(result["authorized"], False)
        self.assertIs(result["admission_eligible"], False)
        return result

    def fault(self, path, replacement, code, state="candidate", noop=False):
        value = fixture(state, noop)
        self.result(value)  # Every one-fault case starts with a proven positive.
        target = value
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = replacement
        self.result(value, code)

    def test_all_fixed_profiles_and_noops(self):
        for state in PHASES:
            for noop in (False, True):
                with self.subTest(state=state, noop=noop):
                    self.result(fixture(state, noop))

    def test_exact_role_set_and_paths(self):
        for section in ("original", "current"):
            for index in range(11):
                rows = fixture()[section]["roles"]
                self.fault((section, "roles"), rows[:index] + rows[index + 1:], "role-set")
                self.fault((section, "roles", index, "role"), "unexpected", "role-set")
                other = (index + 1) % 11
                self.fault((section, "roles", index, "role"), rows[other]["role"], "role-set")
                for path in (rows[other]["path"], rows[index]["path"] + "/../alias", "/unexpected"):
                    self.fault((section, "roles", index, "path"), path, "role-path")
            self.fault((section, "roles"), fixture()[section]["roles"] * 2, "role-set")

    def test_legacy_presence_and_declared_absent_new_outputs(self):
        for index in range(9):
            self.fault(("original", "roles", index, "before"), None, "legacy-required")
        for index in (9, 10):
            for profile in ("before", "restored_before"):
                self.fault(("original", "roles", index, profile), obj("unexpected", "unexpected"), "new-output-absence")
        for index in range(11):
            self.fault(("original", "roles", index, "change"), "adopt", "role-change")

    def test_phase_expected_references(self):
        for state in PHASES:
            for index in range(11):
                self.fault(("current", "roles", index, "object"), obj("foreign", "foreign"),
                           "phase-role-reference", state)
        self.fault(("original", "roles", 1, "candidate", "object_ref"),
                   "synthetic:ordinary-observer-candidate", "object-alias")

    def test_preservation_noop_and_restoration_identities(self):
        for index in range(9):
            self.fault(("original", "roles", index, "candidate", "object_ref"),
                       "synthetic:changed", "unchanged-identity", noop=True)
        self.fault(("original", "roles", 0, "restored_before", "object_ref"),
                   "synthetic:ordinary-observer-before", "restoration-identity")
        self.fault(("original", "roles", 0, "restored_before", "content_ref"),
                   "synthetic:changed", "restore-content")
        self.fault(("original", "roles", 0, "candidate", "content_ref"),
                   "synthetic:ordinary-observer-old", "replace-content")

    def test_original_recovery_owner_and_checkpoint_bindings(self):
        self.fault(("recovery", "reference"), "synthetic:original", "original-recovery-distinct")
        for section in ("recovery", "current"):
            self.fault((section, "original_ref"), "synthetic:recovery", "original-reference")
        self.fault(("original", "reference"), "synthetic:replacement", "original-reference")
        self.fault(("current", "owner_ref"), "synthetic:foreign", "owner-reference")
        for owner in (None, "unknown", "ambiguous"):
            self.fault(("current", "owner_ref"), owner, "reference-shape")
        self.fault(("current", "state"), "prepared", "starting-state")
        self.fault(("recovery", "start_state"), "prepared", "starting-state")
        for section, key in (("current", "generation"), ("original", "generation"), ("recovery", "start_generation")):
            self.fault((section, key), 8, "starting-generation")
            for wrong in (True, False, "7", None, 0):
                self.fault((section, key), wrong, "generation-type")
        for state in ("installing", "rollback-failed", "detached-committed", "cleaned", "unknown"):
            self.fault(("original", "state"), state, "unsupported-state")

    def test_causal_terminal_action_exclusions(self):
        for state, (_, allowed) in PHASES.items():
            for action in ("apply", "commit", "resume", "install", "retry", "renew-receipt",
                           "rollback-exact", "cleanup-committed", "cleanup-rolled-back"):
                if action != allowed:
                    self.fault(("recovery", "action"), action, "state-action", state)
        for state in ("committed", "rolled-back"):
            self.fault(("original", "terminal_audit_ref"), None, "terminal-audit-required", state)
            self.fault(("current", "terminal_audit_ref"), "synthetic:fresh-substitute", "terminal-audit-reference", state)
        self.fault(("original", "terminal_audit_ref"), "synthetic:invented", "preterminal-audit")

    def test_unknown_fields_and_trust_me_claims(self):
        for name, claim in (("authorized", True), ("admission_eligible", True), ("blockers", []),
                            ("locks_held", True), ("audit_complete", True), ("owner_authenticated", True),
                            ("publication", "ambiguous"), ("automatic_retry", True),
                            ("receipt_renewal", True), ("fresh_health", True)):
            for section in (None, "original", "recovery", "current"):
                value = fixture()
                self.result(value)
                (value if section is None else value[section])[name] = claim
                self.result(value, "fields")
        self.fault(("original", "roles", 0, "before", "inode"), 123, "fields")
        self.fault(("current", "roles", 0, "object", "trusted"), True, "fields")

    def test_missing_fields_and_container_types(self):
        for path in ((), ("original",), ("recovery",), ("current",),
                     ("original", "roles", 0), ("current", "roles", 0),
                     ("original", "roles", 0, "before")):
            template = fixture()
            target = template
            for part in path:
                target = target[part]
            for key in target:
                value = fixture()
                self.result(value)
                parent = value
                for part in path:
                    parent = parent[part]
                del parent[key]
                self.result(value, "format" if path == () and key == "format" else "fields")
        for section in ("original", "current", "recovery"):
            for value in (None, [], True, 7, "synthetic:unknown"):
                self.fault((section,), value, "fields")

    def test_types_bounds_and_current_format_confusion(self):
        for format_name in ("home-lab-proxmox-access-evidence-v1",
                            "home-lab-proxmox-predecessor-console-measurement-v1",
                            "home-lab-proxmox-controller-capability-v1", "receipt-v1",
                            "synthetic-only-legacy-transition-classification-v0", None, 1):
            self.fault(("format",), format_name, "format")
        for value in (b"json", 1.5, float("nan"), set(), object()):
            self.result(value, "input-type")
        for value in ("x" * 257, [None] * 33, 2147483648):
            self.result(value, "input-bounds")
        for value in ({1: None}, "\ud800", "\n"):
            self.result(value, "input-type")
        cycle = []
        cycle.append(cycle)
        self.result(cycle, "input-bounds")
        self.result([[[None] * 32] * 32] * 32, "input-bounds")
        self.fault(("original", "owner_ref"), "synthetic:" + "x" * 71, "reference-shape")
        class DictSubclass(dict):
            pass
        self.result(DictSubclass(fixture()), "input-type")
        self.fault(("original", "roles"), {}, "role-set")
        self.fault(("original", "roles", 0, "candidate"), True, "fields")
        self.fault(("original", "owner_ref"), "a" * 64, "reference-shape")
        self.fault(("original", "roles", 0, "candidate", "object_ref"), True, "reference-shape")

    def test_deterministic_no_mutation_or_shared_result_blockers(self):
        value = fixture()
        before = copy.deepcopy(value)
        first = self.result(value)
        self.assertEqual(first, self.result(value))
        self.assertEqual(value, before)
        first["blockers"].clear()
        first["authorized"] = True
        self.result(value)
        self.result(first, "format")

    def test_no_runtime_io_including_source_initialization(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("runtime I/O or import attempted")
        # No imports at all in the classifier; both module initialization and
        # positive/refusal execution run behind tripwires. Source loading above
        # is test-only, exact adjacent source, never a measured helper import.
        self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom))
                             for node in ast.walk(ast.parse(SOURCE))))
        values = [fixture(state) for state in PHASES] + [{}, None]
        compiled = compile(SOURCE, "synthetic-classifier-source", "exec")
        with patch.object(builtins, "open", forbidden), patch.object(builtins, "__import__", forbidden), \
                patch.object(io, "open", forbidden), patch.object(os, "open", forbidden), \
                patch.object(os, "stat", forbidden), patch.object(os, "getenv", forbidden), \
                patch.object(os, "environ", None), patch.object(time, "time", forbidden), \
                patch.object(time, "monotonic", forbidden), patch.object(socket, "socket", forbidden), \
                patch.object(subprocess, "Popen", forbidden):
            namespace = {}
            exec(compiled, namespace)
            for value in values:
                result = namespace["classify"](value)
                self.assertIs(result["authorized"], False)

    def test_in_memory_guard_mutations_are_detected(self):
        probes = [
            ('require(indexed[role]["path"] == path, "role-path")', 'require(True, "role-path")',
             ("current", "roles", 0, "path"), "/alias", "role-path"),
            ('require(recovery["action"] == action, "state-action")', 'require(True, "state-action")',
             ("recovery", "action"), "rollback-exact", "state-action"),
            ('"blockers": list(BLOCKERS)', '"blockers": []', None, None, "synthetic-consistency-only"),
        ]
        for old, new, path, replacement, code in probes:
            with self.subTest(guard=old):
                self.assertEqual(SOURCE.count(old), 1)
                namespace = {}
                exec(compile(SOURCE.replace(old, new), "synthetic-mutant", "exec"), namespace)
                value = fixture("committed")
                if path:
                    target = value
                    for part in path[:-1]:
                        target = target[part]
                    target[path[-1]] = replacement
                self.result(value, code)
                with self.assertRaises(AssertionError):
                    self.result(value, code, namespace["classify"])


if __name__ == "__main__":
    # This is a test-runner constraint only, not a classifier bypass or CLI.
    if not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
        raise SystemExit("synthetic suite requires python3 -I -B -S")
    unittest.main()
