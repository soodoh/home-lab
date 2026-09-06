"""Pure synthetic role/checkpoint grammar; NOT a receipt, journal or authority.

classify() accepts only bounded built-in JSON-shaped values. References denote
asserted consistency inside one call, never hashes of or identities of real
objects. There is no operational CLI, import, collection or publication code.
"""

INPUT_FORMAT = "synthetic-only-legacy-transition-assertions-v0"
OUTPUT_FORMAT = "synthetic-only-legacy-transition-classification-v0"
BLOCKERS = (
    "complete-real-audit-and-closed-support-catalog-unqualified",
    "original-and-recovery-authority-unverified",
    "origin-host-console-and-runtime-unqualified",
    "evidence-specific-freshness-unqualified",
    "source-profile-approval-and-compatibility-unqualified",
    "asynchronous-writer-coordination-unqualified",
    "crash-durable-ownership-and-publication-identity-unverified",
    "original-terminal-audit-authenticity-unverified",
)

# Public role spellings follow bootstrap HELPERS/FIREWALL_TARGETS and the neutral
# builder; the collector is NOT an alias for the preserved private preparer.
ROOT = "/usr/local/libexec/home-lab/"
ROLES = (
    ("ordinary-observer", ROOT + "proxmox-observer", "replace-or-noop"),
    ("package-observer", ROOT + "proxmox-package-candidate-observer", "replace-or-noop"),
    ("plan-transport", ROOT + "proxmox-ansible-plan-transport", "replace-or-noop"),
    ("deploy-activator", ROOT + "proxmox-ansible-deploy-activator", "replace-or-noop"),
    ("ansible-plan-sudo", "/etc/sudoers.d/ansible-plan", "replace-or-noop"),
    ("private-preparer", ROOT + "proxmox-private-preparer", "preserve"),
    ("firewall-helper", ROOT + "proxmox-firewall-transaction", "preserve"),
    ("firewall-transport", ROOT + "proxmox-firewall-transport", "preserve"),
    ("firewall-sudo", "/etc/sudoers.d/firewall-apply", "preserve"),
    ("protected-collector", ROOT + "proxmox-protected-collector", "new-output"),
    ("controller-observer", ROOT + "proxmox-controller-observer", "new-output"),
)
# Deliberately no mixed installation, failed/ambiguous publication, detachment,
# fully-cleaned, or retry checkpoints: those need an unimplemented protocol.
STATES = {
    "prepared": ("before", "rollback-exact"),
    "candidate": ("candidate", "rollback-exact"),
    "rollback-restored": ("restored_before", "rollback-exact"),
    "committed": ("candidate", "cleanup-committed"),
    "rolled-back": ("restored_before", "cleanup-rolled-back"),
}


class Refusal(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def bounded(value):
    budget = [4096]

    def visit(item, depth):
        budget[0] -= 1
        require(budget[0] >= 0 and depth <= 12, "input-bounds")
        kind = type(item)
        if kind is dict:
            require(len(item) <= 32, "input-bounds")
            for key, child in item.items():
                require(type(key) is str, "input-type")
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif kind is list:
            require(len(item) <= 32, "input-bounds")
            for child in item:
                visit(child, depth + 1)
        elif kind is str:
            require(len(item) <= 256, "input-bounds")
            require(all(32 <= ord(char) <= 126 for char in item), "input-type")
        elif kind is int:
            require(0 <= item <= 2147483647, "input-bounds")
        else:
            require(item is None or kind is bool, "input-type")

    visit(value, 0)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), "fields")


def reference(value):
    require(type(value) is str and value.startswith("synthetic:")
            and 10 < len(value) <= 80
            and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in value[10:]),
            "reference-shape")


def object_shape(value):
    fields(value, "content_ref object_ref")
    reference(value["content_ref"])
    reference(value["object_ref"])


def role_rows(rows, original):
    require(type(rows) is list and len(rows) == len(ROLES), "role-set")
    indexed = {}
    for row in rows:
        fields(row, "role path change before candidate restored_before" if original
               else "role path object")
        require(type(row["role"]) is str and row["role"] not in indexed, "role-set")
        indexed[row["role"]] = row
    require(set(indexed) == {role for role, _, _ in ROLES}, "role-set")
    for role, path, _ in ROLES:
        require(indexed[role]["path"] == path, "role-path")
    return indexed


def check_roles(original, current, profile):
    expected = role_rows(original, True)
    observed = role_rows(current, False)
    identities = {}
    for role, _, category in ROLES:
        row = expected[role]
        change = row["change"]
        allowed = ("replace", "noop") if category == "replace-or-noop" else (category,)
        require(change in allowed, "role-change")
        before, candidate, restored = (row[key] for key in
                                       ("before", "candidate", "restored_before"))
        object_shape(candidate)
        if category == "new-output":
            require(before is None and restored is None, "new-output-absence")
        else:
            require(before is not None and restored is not None, "legacy-required")
            object_shape(before)
            object_shape(restored)
            if change in ("noop", "preserve"):
                require(before == candidate == restored, "unchanged-identity")
            else:
                require(before["content_ref"] != candidate["content_ref"], "replace-content")
                require(restored["content_ref"] == before["content_ref"], "restore-content")
                require(len({obj["object_ref"] for obj in (before, candidate, restored)}) == 3,
                        "restoration-identity")
        for obj in (before, candidate, restored):
            if obj is not None:
                identity = obj["object_ref"]
                require(identity not in identities or identities[identity] == role, "object-alias")
                identities[identity] = role
        actual = observed[role]["object"]
        if actual is not None:
            object_shape(actual)
        require(actual == row[profile], "phase-role-reference")


def check(value):
    bounded(value)
    require(type(value) is dict, "fields")
    require(value.get("format") == INPUT_FORMAT, "format")
    fields(value, "format original recovery current")
    original, recovery, current = (value[key] for key in ("original", "recovery", "current"))
    fields(original, "reference owner_ref state generation terminal_audit_ref roles")
    fields(recovery, "reference original_ref start_state start_generation action")
    fields(current, "original_ref owner_ref state generation terminal_audit_ref roles")
    for ref in (original["reference"], original["owner_ref"], recovery["reference"],
                recovery["original_ref"], current["original_ref"], current["owner_ref"]):
        reference(ref)
    require(original["reference"] != recovery["reference"], "original-recovery-distinct")
    require(recovery["original_ref"] == current["original_ref"] == original["reference"],
            "original-reference")
    require(current["owner_ref"] == original["owner_ref"], "owner-reference")
    state = original["state"]
    require(type(state) is str and state in STATES, "unsupported-state")
    require(current["state"] == recovery["start_state"] == state, "starting-state")
    for generation in (original["generation"], current["generation"], recovery["start_generation"]):
        require(type(generation) is int and 1 <= generation <= 2147483647, "generation-type")
    require(original["generation"] == current["generation"] == recovery["start_generation"],
            "starting-generation")
    profile, action = STATES[state]
    require(recovery["action"] == action, "state-action")
    terminal = state in ("committed", "rolled-back")
    if terminal:
        require(original["terminal_audit_ref"] is not None, "terminal-audit-required")
        reference(original["terminal_audit_ref"])
    else:
        require(original["terminal_audit_ref"] is None, "preterminal-audit")
    require(current["terminal_audit_ref"] == original["terminal_audit_ref"], "terminal-audit-reference")
    check_roles(original["roles"], current["roles"], profile)


def classify(value):
    """Return only syntax/consistency classification with unconditional blockers.

    The original is an asserted frozen checkpoint, not an authenticated journal.
    No comparison across calls, profile selection, terminal audit verification,
    historical restamping, health check or recovery permission is implemented.
    """
    code = "synthetic-consistency-only"
    status = "well-formed-for-further-qualification"
    try:
        check(value)
    except Refusal as error:
        code = str(error)
        status = "refused"
    return {"format": OUTPUT_FORMAT, "status": status, "classification": code,
            "authorized": False, "admission_eligible": False,
            "blockers": list(BLOCKERS)}
