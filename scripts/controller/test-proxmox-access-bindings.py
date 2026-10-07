#!/usr/bin/env python3
"""Exercise exact read-only token ACL admission, including scoped grants."""

from copy import deepcopy
import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "infrastructure/host-lifecycle/proxmox/protected-collector-template.py"


class AccessBindingTests(unittest.TestCase):
    def setUp(self):
        self.identity = "fixture@pam!plan"
        self.binding = {
            "principal": "plan", "primaryAcl": "/", "privilegeSeparation": True,
            "role": "FixtureAudit", "additionalAcls": [
                {"path": "/vms/100", "role": "FixtureDisk"},
                {"path": "/storage/local", "role": "FixtureStorage", "propagate": False},
            ],
        }
        source = TEMPLATE.read_text().replace("'@PROTECTED_SPEC@'", repr(json.dumps({})))
        self.namespace = {"__name__": "protected_collector_fixture"}
        exec(compile(source, str(TEMPLATE), "exec"), self.namespace)
        self.namespace["SPEC"] = {"pveAccessBindings": [self.binding]}
        self.commands = []

        def metadata(command):
            self.commands.append(command)
            return json.dumps({"privsep": 1})

        self.namespace["run"] = metadata
        self.acls = [
            {"path": "/", "roleid": "FixtureAudit", "ugid": self.identity, "propagate": 1, "type": "token"},
            {"path": "/vms/100", "roleid": "FixtureDisk", "ugid": self.identity, "propagate": 1, "type": "token"},
            {"path": "/storage/local", "roleid": "FixtureStorage", "ugid": self.identity, "propagate": 0, "type": "token"},
        ]

    def matches(self, acls=None):
        return self.namespace["token_policy_valid"](
            self.identity + "=synthetic-secret", "plan", self.acls if acls is None else acls, self.identity,
        )

    def test_exact_scoped_and_legacy_bindings_match_with_only_metadata_read(self):
        self.assertTrue(self.matches())
        self.assertEqual(self.commands, [(
            "/usr/bin/pvesh", "get", "/access/users/fixture@pam/token/plan", "--output-format", "json",
        )])
        self.binding["additionalAcls"].pop()
        self.assertTrue(self.matches(self.acls[:2]))

    def test_wrong_propagation_is_refused_in_both_directions(self):
        for index in (1, 2):
            with self.subTest(index=index):
                acls = deepcopy(self.acls)
                acls[index]["propagate"] = 1 - acls[index]["propagate"]
                self.assertFalse(self.matches(acls))

    def test_missing_extra_duplicate_and_retargeted_grants_are_refused(self):
        other_store = {**self.acls[2], "path": "/storage/other"}
        other_role = {**self.acls[2], "roleid": "FixtureAdmin"}
        for acls in (self.acls[:2], [*self.acls, other_store], [*self.acls, self.acls[2]],
                     [*self.acls[:2], other_store], [*self.acls[:2], other_role]):
            with self.subTest(acls=acls):
                self.assertFalse(self.matches(acls))

    def test_desired_propagation_requires_a_boolean(self):
        for value in (None, "false", "true", 0, 1, [], {}):
            with self.subTest(value=value):
                self.binding["additionalAcls"][1]["propagate"] = value
                self.assertFalse(self.matches())

    def test_unseparated_token_and_wrong_identity_are_refused(self):
        self.namespace["run"] = lambda command: json.dumps({"privsep": 0})
        self.assertFalse(self.matches())
        self.namespace["run"] = lambda command: json.dumps({"privsep": 1})
        self.assertFalse(self.namespace["token_policy_valid"](
            self.identity + "=synthetic-secret", "plan", self.acls, "fixture@pam!other",
        ))


if __name__ == "__main__":
    unittest.main()
