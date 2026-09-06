#!/usr/bin/python3 -IBS
"""Offline imported content diagnostic; never access evidence or admission authority.

Invoke directly (fixed isolated shebang), or /usr/bin/python3 -I -B -S SCRIPT ... .
See docs/proxmox-controller-capability-candidate.md for bounds and exclusions.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

FORMAT = "home-lab-tailscale-access-diagnostic-v1"
BLOCKERS = ["binary-to-json-linkage-unproven", "live-collection-origin-unproven",
            "execution-qualification-unproven", "independent-policy-review-provenance-unproven"]
HELPER_SHA256 = "1535c83268111bd15099b9a6e21a4cc8da8e97802a12995b4e805a07b624d8c9"
LIMITS = {"plan": 2 * 1024 * 1024, "live_before": 256 * 1024,
          "live_after": 256 * 1024, "expected_policy": 256 * 1024,
          "headers_before": 16 * 1024, "headers_after": 16 * 1024}
MAX_TOTAL = 3 * 1024 * 1024
MAX_DEPTH = 48
MAX_NODES = 100000
DESCRIPTOR = {"address": "terraform_data.tailscale_policy[0]", "mode": "managed",
              "type": "terraform_data", "name": "tailscale_policy", "index": 0,
              "provider_name": "terraform.io/builtin/terraform"}


class Invalid(ValueError):
    """Only fixed, public error codes cross the CLI boundary."""


def require(condition, code):
    if not condition:
        raise Invalid(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, keys, code="plan-shape"):
    require(type(value) is dict and set(value) == set(keys.split()), code)


def subset(value, required, optional="", code="plan-shape"):
    require(type(value) is dict and set(required.split()) <= set(value)
            and set(value) <= set((required + " " + optional).split()), code)


def same(left, right):
    return canonical(left) == canonical(right)


class Budget:
    def __init__(self):
        self.nodes = 0

    def parse(self, raw, limit):
        require(type(raw) is bytes and 0 < len(raw) <= limit, "input-bound")

        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, "json-duplicate-key")
                result[key] = value
            return result

        def number(value):
            require(len(value) <= 20, "json-number")
            result = int(value)
            require(-(2**63) <= result < 2**63, "json-number")
            return result

        def reject(_):
            raise Invalid("json-number")

        try:
            value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                               parse_constant=reject, parse_float=reject, parse_int=number)
            stack = [(value, 0)]
            while stack:
                item, depth = stack.pop()
                self.nodes += 1
                require(depth <= MAX_DEPTH and self.nodes <= MAX_NODES, "json-bound")
                if type(item) is dict:
                    stack.extend((v, depth + 1) for v in item.values())
                    stack.extend((k, depth + 1) for k in item)
                elif type(item) is list:
                    stack.extend((v, depth + 1) for v in item)
                elif type(item) is str:
                    item.encode("utf-8", "strict")
            return value
        except (UnicodeError, RecursionError, ValueError) as error:
            if isinstance(error, Invalid):
                raise
            raise Invalid("json-invalid") from None


def strings(value):
    require(type(value) is list and 0 < len(value) <= 1024, "policy-structure")
    require(all(type(v) is str and 0 < len(v) <= 1024 and
                not any(ord(c) < 32 or ord(c) == 127 for c in v) for v in value),
            "policy-structure")
    require(len(set(value)) == len(value), "policy-structure")


def policy_structure(value):
    # Deliberately the reviewed source's subset, not a general Tailscale API schema.
    exact(value, "tagOwners grants ssh tests sshTests", "policy-structure")
    require(type(value["tagOwners"]) is dict and bool(value["tagOwners"]), "policy-structure")
    for tag, owners in value["tagOwners"].items():
        require(re.fullmatch(r"tag:[a-z][a-z0-9-]*", tag) is not None, "policy-structure")
        strings(owners)
    for section in ("grants", "ssh", "tests", "sshTests"):
        require(type(value[section]) is list and 0 < len(value[section]) <= 1024, "policy-structure")
        for entry in value[section]:
            if section == "grants":
                exact(entry, "src dst ip", "policy-structure")
                for field in entry:
                    strings(entry[field])
                for port in entry["ip"]:
                    require(re.fullmatch(r"tcp:[0-9]{1,5}", port) is not None and
                            1 <= int(port[4:]) <= 65535, "policy-structure")
            elif section == "ssh":
                exact(entry, "action src dst users", "policy-structure")
                require(entry["action"] == "accept", "policy-structure")
                for field in ("src", "dst", "users"):
                    strings(entry[field])
            else:
                required = "src proto" if section == "tests" else "src dst"
                subset(entry, required, "accept deny", "policy-structure")
                strings([entry["src"]])
                require("accept" in entry or "deny" in entry, "policy-structure")
                if section == "tests":
                    require(entry["proto"] == "tcp", "policy-structure")
                else:
                    strings(entry["dst"])
                for field in ("accept", "deny"):
                    if field in entry:
                        strings(entry[field])
                        if section == "tests":
                            for target in entry[field]:
                                host, sep, port = target.rpartition(":")
                                require(bool(host) and sep == ":" and
                                        re.fullmatch(r"[0-9]{1,5}", port) is not None and
                                        1 <= int(port) <= 65535, "policy-structure")
                require(not (set(entry.get("accept", [])) & set(entry.get("deny", []))),
                        "policy-structure")


def headers(raw, body):
    require(type(raw) is bytes and 0 < len(raw) <= LIMITS["headers_before"], "headers-bound")
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeError:
        raise Invalid("headers-invalid") from None
    lines = text.split("\r\n")
    require(len(lines) <= 102 and lines[-2:] == ["", ""], "headers-invalid")
    require(re.fullmatch(r"HTTP/(?:1\.[01]|2) 200(?: OK)?", lines[0]) is not None,
            "headers-status")
    fields = {}
    for line in lines[1:-2]:
        match = re.fullmatch(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([\x20-\x7e]*)", line)
        require(match is not None, "headers-invalid")
        key, value = match.group(1).lower(), match.group(2).strip()
        require(key not in fields, "headers-duplicate")
        fields[key] = value
    require(not ({"location", "content-encoding", "transfer-encoding", "www-authenticate",
                  "proxy-authenticate", "refresh"} & set(fields)), "headers-unsupported")
    require(re.fullmatch(r'"[\x21\x23-\x7e]+"', fields.get("etag", "")) is not None,
            "etag-invalid")
    require(re.fullmatch(r"application/json(?:; *charset=utf-8)?",
                         fields.get("content-type", "").lower()) is not None, "headers-content-type")
    if "content-length" in fields:
        require(fields["content-length"] == str(len(body)), "headers-content-length")
    return fields["etag"]


def resource_values(value, budget, helper):
    exact(value, "id input output triggers_replace")
    require(type(value["id"]) is str and 0 < len(value["id"]) <= 256 and
            value["triggers_replace"] is None, "resource-values")
    exact(value["input"], "policy_json policy_sha256")
    require(same(value["input"], value["output"]), "resource-output")
    raw = value["input"]["policy_json"]
    require(type(raw) is str, "policy-json-type")
    raw = raw.encode("utf-8")
    require(value["input"]["policy_sha256"] == sha(raw), "embedded-policy-hash")
    parsed = budget.parse(raw, LIMITS["expected_policy"])
    policy_structure(parsed)
    require(same(parsed, helper.parse_policy_json(raw.decode("utf-8"))), "helper-policy")
    return parsed


def values_root(value, wanted):
    subset(value, "root_module", "outputs")
    require(value.get("outputs", {}) == {}, "plan-outputs")
    exact(value["root_module"], "resources")
    resources = value["root_module"]["resources"]
    require(type(resources) is list and len(resources) == 1, "plan-resources")
    resource = resources[0]
    exact(resource, " ".join(DESCRIPTOR) + " schema_version values sensitive_values")
    require(same({k: resource[k] for k in DESCRIPTOR}, DESCRIPTOR) and
            type(resource["schema_version"]) is int and resource["schema_version"] == 0,
            "resource-descriptor")
    require(same(resource["values"], wanted), "plan-values-inconsistent")
    require(same(resource["sensitive_values"], {"input": {}, "output": {}}), "plan-sensitive")


def plan_policy(plan, budget, helper):
    subset(plan, "format_version terraform_version planned_values resource_changes prior_state configuration timestamp errored",
           "variables output_changes resource_drift deferred_changes complete applyable checks")
    require(plan["format_version"] == "1.2" and type(plan["terraform_version"]) is str and
            re.fullmatch(r"1\.(?:11|12)\.[0-9]+", plan["terraform_version"]) is not None,
            "plan-version")
    require(plan["errored"] is False and plan.get("complete", True) is True and
            plan.get("applyable", False) is False, "plan-incomplete")
    require(type(plan["timestamp"]) is str and
            re.fullmatch(r"[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}Z", plan["timestamp"]),
            "plan-timestamp")
    for field in ("resource_drift", "deferred_changes", "checks"):
        require(plan.get(field, []) == [], "plan-pending-work")
    require(plan.get("output_changes", {}) == {}, "plan-outputs")
    if "variables" in plan:
        exact(plan["variables"], "tailscale_enable_management")
        require(same(plan["variables"]["tailscale_enable_management"], {"value": True}), "plan-disabled")
    changes = plan["resource_changes"]
    require(type(changes) is list and len(changes) == 1, "plan-resources")
    resource = changes[0]
    exact(resource, " ".join(DESCRIPTOR) + " change")
    require(same({k: resource[k] for k in DESCRIPTOR}, DESCRIPTOR), "resource-descriptor")
    change = resource["change"]
    exact(change, "actions before after after_unknown before_sensitive after_sensitive")
    require(change["actions"] == ["no-op"] and change["after_unknown"] == {}, "plan-not-noop")
    for field in ("before_sensitive", "after_sensitive"):
        require(same(change[field], {"input": {}, "output": {}}), "plan-sensitive")
    before = resource_values(change["before"], budget, helper)
    after = resource_values(change["after"], budget, helper)
    require(same(change["before"], change["after"]), "resource-inconsistent")
    require(same(helper.policy_from_plan(plan, "before"), before) and
            same(helper.policy_from_plan(plan, "after"), after), "helper-policy")
    values_root(plan["planned_values"], change["after"])
    prior = plan["prior_state"]
    exact(prior, "format_version terraform_version values")
    require(prior["format_version"] == "1.0" and prior["terraform_version"] == plan["terraform_version"],
            "plan-version")
    values_root(prior["values"], change["before"])
    config = plan["configuration"]
    exact(config, "provider_config root_module")
    providers = config["provider_config"]
    subset(providers, "terraform", "tailscale", "plan-configuration")
    require(same(providers["terraform"], {"name": "terraform", "full_name": "terraform.io/builtin/terraform"}), "plan-configuration")
    if "tailscale" in providers:
        # This UNUSED root entry is bounded opaque imported metadata, not a
        # reviewed descriptor/version or qualified dependency. Never execute it.
        opaque = providers["tailscale"]
        require(type(opaque) is dict and bool(opaque) and len(canonical(opaque)) <= 16384,
                "plan-unused-provider")
        pending = [opaque]
        while pending:
            value = pending.pop()
            if type(value) is dict:
                require(not any("alias" in k.lower() or "module" in k.lower() for k in value),
                        "plan-unused-provider")
                pending.extend(value.values())
            elif type(value) is list:
                pending.extend(value)
            elif type(value) is str:
                require(not value.startswith(("module.", "tailscale.", "terraform.")), "plan-unused-provider")
    subset(config["root_module"], "resources", "variables")
    variables = config["root_module"].get("variables")
    require((variables is not None) == ("variables" in plan), "plan-configuration")
    if "variables" in config["root_module"]:
        exact(variables, "tailscale_enable_management")
        variable = variables["tailscale_enable_management"]
        exact(variable, "type default")
        require(variable["type"] == "bool" and type(variable["default"]) is bool, "plan-configuration")
    configured = config["root_module"]["resources"]
    require(type(configured) is list and len(configured) == 1, "plan-configuration")
    item = configured[0]
    exact(item, "address mode type name provider_config_key expressions schema_version count_expression")
    expected = {k: v for k, v in DESCRIPTOR.items() if k in ("mode", "type", "name")}
    expected.update(address="terraform_data.tailscale_policy", provider_config_key="terraform", schema_version=0)
    require(same({k: item[k] for k in expected}, expected), "plan-configuration")
    exact(item["expressions"], "input")
    # Expressions are imported metadata, not evaluated or source qualification.
    for expression, references in ((item["expressions"]["input"], ["local.policy_json", "local.policy_json"]),
                                   (item["count_expression"], ["var.tailscale_enable_management"])):
        require(type(expression) is dict and set(expression) in ({"constant_value"}, {"references"}),
                "plan-configuration")
        if "references" in expression:
            require(expression["references"] == references, "plan-configuration")
            require(variables is not None, "plan-configuration")
    if "constant_value" in item["expressions"]["input"]:
        require(same(item["expressions"]["input"]["constant_value"], change["after"]["input"]), "plan-configuration")
    if "constant_value" in item["count_expression"]:
        require(same(item["count_expression"]["constant_value"], 1), "plan-disabled")
    return before


def result(inputs=None):
    return {"format": FORMAT, "authorized": False, "admission_eligible": False,
            "origin": "unqualified-import", "blockers": list(BLOCKERS),
            "content_consistent": False, "inputs": inputs or {}, "errors": [],
            "limitations": ["unused-root-tailscale-provider-metadata-not-verified",
                            "policy-structure-only-no-api-tests-or-live-canaries"]}


def verify(inputs, expected_sha256, helper):
    """Pure bounded byte verifier. The caller supplies the fixed reviewed helper."""
    output = result()
    try:
        require(type(inputs) is dict and set(inputs) == set(LIMITS), "input-set")
        require(all(type(v) is bytes and 0 < len(v) <= LIMITS[k] for k, v in inputs.items())
                and sum(map(len, inputs.values())) <= MAX_TOTAL, "input-bound")
        output["inputs"] = {k: {"sha256": sha(v), "size": len(v)} for k, v in inputs.items()}
        require(type(expected_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", expected_sha256), "expected-digest-invalid")
        require(sha(inputs["expected_policy"]) == expected_sha256, "expected-digest-mismatch")
        budget = Budget()
        policies = [budget.parse(inputs[k], LIMITS[k]) for k in ("expected_policy", "live_before", "live_after")]
        for policy in policies:
            policy_structure(policy)
        plan = budget.parse(inputs["plan"], LIMITS["plan"])
        policies.append(plan_policy(plan, budget, helper))
        hashes = [helper.canonical_policy_sha256(p) for p in policies]
        require(len(set(hashes)) == 1, "policy-mismatch")
        helper.validate_before_identity(hashes[-1], hashes[1])
        etags = [headers(inputs["headers_" + side], inputs["live_" + side]) for side in ("before", "after")]
        for etag in etags:
            helper.validate_etag("imported", etag)
        require(etags[0] == etags[1], "etag-changed")
        output.update(content_consistent=True, canonical_policy_sha256=hashes[0],
                      etag_sha256=sha(etags[0].encode("ascii")))
    except Invalid as error:
        output["errors"] = [str(error)]
    except Exception:
        output["errors"] = ["content-invalid"]
    return output


def identity(info, directory=False):
    fields = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
    return fields if directory else fields + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class PrivateReads:
    """Retain descriptor ancestry and recheck named inodes AND exact bytes at end."""
    def __init__(self):
        self.nodes = []
        self.files = []

    def close(self):
        for fd, *_ in reversed(self.nodes):
            os.close(fd)
        self.nodes.clear()

    def read(self, path, limit, source=False):
        require(type(path) is str and path.startswith("/") and
                all(p not in ("", ".", "..") for p in path.split("/")[1:]), "input-path")
        parts = path.split("/")[1:]
        parent = None
        for index, name in enumerate(["/"] + parts):
            directory = index < len(parts)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory:
                flags |= os.O_DIRECTORY
            fd = os.open(name, flags, dir_fd=parent)
            info = os.fstat(fd)
            self.nodes.append((fd, parent, name, identity(info, directory), directory))
            mode = stat.S_IMODE(info.st_mode)
            if directory:
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()), "input-ancestry")
                # Only canonical root-owned sticky temporary roots are exceptions.
                prefix = "/" + "/".join(parts[:index])
                sticky_tmp = prefix in ("/tmp", "/private/tmp") and info.st_uid == 0 and mode == 0o1777
                require(not mode & 0o022 or sticky_tmp, "input-ancestry")
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                        info.st_uid == os.getuid(), "input-metadata")
                require(mode in ((0o400, 0o600, 0o644, 0o755) if source else (0o400, 0o600)), "input-mode")
                require(0 < info.st_size <= limit, "input-bound")
            parent = fd
        raw = self.read_fd(fd, limit)
        require(len(raw) == info.st_size, "input-replaced")
        self.files.append((fd, raw, limit))
        self.check()
        return raw

    @staticmethod
    def read_fd(fd, limit):
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        require(0 < len(raw) <= limit, "input-bound")
        return raw

    def check(self):
        def metadata():
            for fd, parent, name, saved, directory in self.nodes:
                require(identity(os.fstat(fd), directory) == saved and
                        identity(os.stat(name, dir_fd=parent, follow_symlinks=False), directory) == saved,
                        "input-replaced")
        metadata()
        for fd, raw, limit in self.files:
            require(self.read_fd(fd, limit) == raw, "input-replaced")
        metadata()


def load_helper(reads):
    path = os.path.abspath(__file__)
    # Source reads never consult importlib or __pycache__, including unchecked pycs.
    reads.read(path, 64 * 1024, source=True)
    raw = reads.read(str(Path(path).with_name("tailscale-policy.py")), 32 * 1024, source=True)
    require(sha(raw) == HELPER_SHA256, "helper-source-mismatch")
    module = types.ModuleType("reviewed_tailscale_policy")
    exec(compile(raw, "<reviewed-tailscale-policy>", "exec", dont_inherit=True), module.__dict__)
    reads.check()
    return module


def main(argv=None):
    output = result()
    reads = PrivateReads()
    try:
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1 and
                sys.flags.dont_write_bytecode == 1, "isolated-startup-required")
        args = sys.argv[1:] if argv is None else argv
        names = {"--" + k.replace("_", "-"): k for k in LIMITS}
        names["--expected-sha256"] = "expected_sha256"
        require(len(args) == 2 * len(names), "cli-arguments")
        options = {}
        for key, value in zip(args[::2], args[1::2]):
            require(key in names and names[key] not in options, "cli-arguments")
            options[names[key]] = value
        helper = load_helper(reads)
        inputs = {k: reads.read(options[k], limit) for k, limit in LIMITS.items()}
        output = verify(inputs, options["expected_sha256"], helper)
        reads.check()
    except Invalid as error:
        output = result()
        output["errors"] = [str(error)]
    except Exception:
        output = result()
        output["errors"] = ["input-or-source-invalid"]
    finally:
        reads.close()
    sys.stdout.buffer.write(canonical(output))
    return 0 if output["content_consistent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
