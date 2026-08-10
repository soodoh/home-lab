#!/usr/bin/env python3
"""Focused tests for saved-plan Tailscale policy binding."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

HELPER = Path(__file__).with_name("tailscale-gateway-policy.py")


def load_helper():
    spec = importlib.util.spec_from_file_location("tailscale_policy", HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {HELPER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load_helper()
BEFORE = "a" * 64
AFTER = "b" * 64
ETAG = '"policy-etag"'


class CanonicalPolicyTests(unittest.TestCase):
    def test_canonicalization_is_sorted_and_stable(self) -> None:
        value = {"z": [2, 1], "a": {"y": True}}
        self.assertEqual(policy.canonical_policy(value), '{"a":{"y":true},"z":[2,1]}\n')
        self.assertEqual(
            policy.canonical_policy_sha256(value),
            policy.canonical_policy_sha256(json.loads(policy.canonical_policy(value))),
        )

    def test_duplicate_keys_and_non_objects_are_rejected(self) -> None:
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy_json('{"a":1,"a":2}')
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy_json("[]")

    def test_exact_policy_resource_is_extracted_from_plan(self) -> None:
        plan = {
            "resource_changes": [{
                "address": "terraform_data.tailscale_policy[0]",
                "change": {
                    "before": {"input": {"policy_json": '{"grants":[]}'}},
                    "after": {"input": {"policy_json": '{"grants":[1]}'}},
                },
            }]
        }
        self.assertEqual(policy.policy_from_plan(plan, "before"), {"grants": []})
        self.assertEqual(policy.policy_from_plan(plan, "after"), {"grants": [1]})
        plan["resource_changes"].append(plan["resource_changes"][0])
        with self.assertRaises(policy.PolicyError):
            policy.policy_from_plan(plan, "after")


class IdentityTests(unittest.TestCase):
    def test_before_identity_requires_exact_sha(self) -> None:
        policy.validate_before_identity(BEFORE, BEFORE)
        with self.assertRaises(policy.PolicyError):
            policy.validate_before_identity(BEFORE, AFTER)

    def test_apply_disposition_posts_only_on_exact_sha_and_etag(self) -> None:
        self.assertEqual(policy.apply_disposition(BEFORE, ETAG, BEFORE, AFTER, ETAG), "post")
        self.assertEqual(policy.apply_disposition(AFTER, '"new"', BEFORE, AFTER, ETAG), "recovered")
        with self.assertRaises(policy.PolicyError):
            policy.apply_disposition(BEFORE, '"other"', BEFORE, AFTER, ETAG)
        with self.assertRaises(policy.PolicyError):
            policy.apply_disposition(BEFORE, ETAG, BEFORE, BEFORE, ETAG)

    def test_invalid_hashes_and_etags_are_rejected(self) -> None:
        for sha in ("", "A" * 64, "a" * 63):
            with self.subTest(sha=sha), self.assertRaises(policy.PolicyError):
                policy.validate_policy_sha("test", sha)
        for etag in ("", "bare", '"bad\n"'):
            with self.subTest(etag=etag), self.assertRaises(policy.PolicyError):
                policy.validate_etag("test", etag)


if __name__ == "__main__":
    unittest.main()
