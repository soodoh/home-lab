#!/usr/bin/env python3
"""Verify an exact package transaction against fresh isolated authenticated APT metadata."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

COMMAND_TIMEOUT_SECONDS = 180
APPLY_TIMEOUT_SECONDS = 3_600
KEYRING_TIMEOUT_SECONDS = 30
MAX_KEYRING_BYTES = 1_048_576
MAX_MANIFEST_BYTES = 524_288
PACKAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9+.-]+(?::[a-z0-9][a-z0-9-]*)?$")
VERSION_PATTERN = re.compile(r"^(?:[0-9]+:)?[0-9][0-9A-Za-z.+:~]*(?:-[0-9A-Za-z.+~]+)*$")


def fail(message: str) -> None:
    raise SystemExit(f"apt_package_transaction=failed reason={message}")


def sanitized_environment() -> dict[str, str]:
    return {
        "DEBIAN_FRONTEND": "noninteractive",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }


def run_command(argv: list[str], timeout: int = COMMAND_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=sanitized_environment(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        fail(f"command_timeout command={Path(argv[0]).name}")


def verified_keyring(keyring: dict[str, object], root: Path) -> Path:
    expected = keyring.get("sha256")
    source_url = keyring.get("source_url")
    name = keyring.get("name")
    if not isinstance(expected, str) or not isinstance(name, str):
        fail("keyring_shape")
    if source_url is None:
        path_value = keyring.get("path")
        if not isinstance(path_value, str):
            fail(f"keyring_path name={name}")
        path = Path(path_value)
    else:
        if not isinstance(source_url, str) or not source_url.startswith("https://"):
            fail(f"keyring_url_invalid name={name}")
        path = root / f"{name}.gpg"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(source_url, timeout=KEYRING_TIMEOUT_SECONDS) as response:
                if response.geturl() != source_url:
                    fail(f"keyring_redirect name={name}")
                content = response.read(MAX_KEYRING_BYTES + 1)
        except TimeoutError:
            fail(f"keyring_timeout name={name}")
        if len(content) > MAX_KEYRING_BYTES:
            fail(f"keyring_too_large name={name}")
        path.write_bytes(content)
        path.chmod(0o600)
    if not path.exists() or not path.is_file():
        fail(f"keyring_missing name={name}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        fail(f"keyring_checksum name={name}")
    return path.resolve()


def render_source(repository: dict[str, object], signed_by: Path) -> str:
    required_lists = ["types", "uris", "suites", "components"]
    if any(not isinstance(repository.get(key), list) for key in required_lists):
        fail("repository_shape")
    return "\n".join(
        [
            f"Types: {' '.join(repository['types'])}",
            f"URIs: {' '.join(repository['uris'])}",
            f"Suites: {' '.join(repository['suites'])}",
            f"Components: {' '.join(repository['components'])}",
            f"Signed-By: {signed_by}",
            "",
        ]
    )


def apt_options(
    source_parts: Path,
    config_parts: Path,
    lists: Path,
    cache: Path,
    log: Path,
    *,
    no_locking: bool,
) -> list[str]:
    options = [
        "-o", "Dir::Etc::main=/dev/null",
        "-o", f"Dir::Etc::parts={config_parts}",
        "-o", "Dir::Etc::sourcelist=/dev/null",
        "-o", f"Dir::Etc::sourceparts={source_parts}",
        "-o", f"Dir::State::lists={lists}",
        "-o", "Dir::State::status=/var/lib/dpkg/status",
        "-o", f"Dir::Cache={cache}",
        "-o", f"Dir::Log={log}",
        "-o", "APT::Get::List-Cleanup=1",
        "-o", "Acquire::Retries=3",
        "-o", "Acquire::http::Timeout=20",
        "-o", "Acquire::https::Timeout=20",
        "-o", "Acquire::MaxReleaseFileSize=16777216",
        "-o", "Acquire::MaxFileSize=536870912",
    ]
    if no_locking:
        options.extend(["-o", "Debug::NoLocking=1"])
    return options


def transaction_command(options: list[str], package_specs: list[str], *, apply: bool) -> list[str]:
    mode = ["--yes"] if apply else ["--simulate"]
    return [
        "/usr/bin/apt-get",
        *options,
        *mode,
        "--no-remove",
        "--no-install-recommends",
        "--no-allow-downgrades",
        "install",
        *package_specs,
    ]


def package_architecture(name: str) -> str | None:
    return name.rsplit(":", 1)[1] if ":" in name else None


def validate_manifest(manifest: object) -> tuple[str, dict[str, str]]:
    if not isinstance(manifest, dict) or sorted(manifest) != ["architecture", "packages", "provenance", "version"] or manifest.get("version") != 1:
        fail("manifest_shape")
    architecture = manifest.get("architecture")
    packages = manifest.get("packages")
    if not isinstance(architecture, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture):
        fail("manifest_architecture")
    if not isinstance(packages, list) or not packages:
        fail("manifest_packages")
    expected: dict[str, str] = {}
    for entry in packages:
        if not isinstance(entry, dict) or sorted(entry) != ["name", "version"]:
            fail("manifest_package_shape")
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or PACKAGE_PATTERN.fullmatch(name) is None:
            fail("manifest_package_name")
        if not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None:
            fail(f"manifest_package_version package={name}")
        qualifier = package_architecture(name)
        if qualifier is not None and qualifier != architecture:
            fail(f"manifest_foreign_architecture package={name}")
        if name in expected:
            fail(f"manifest_duplicate package={name}")
        expected[name] = version

    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict) or sorted(provenance) != ["installedInventory", "solverResult"]:
        fail("manifest_provenance_shape")
    inventory = provenance.get("installedInventory")
    if (not isinstance(inventory, dict)
            or sorted(inventory) != ["format", "installedRecords", "sha256"]
            or inventory.get("format") != "dpkg-query-status-tsv-v1"
            or not isinstance(inventory.get("installedRecords"), int)
            or inventory["installedRecords"] < 1
            or not isinstance(inventory.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", inventory["sha256"]) is None):
        fail("manifest_inventory_provenance")
    solver = provenance.get("solverResult")
    if (not isinstance(solver, dict)
            or sorted(solver) != ["changes", "format", "sha256"]
            or solver.get("format") != "apt-get-simulate-v1"
            or not isinstance(solver.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", solver["sha256"]) is None
            or not isinstance(solver.get("changes"), list)
            or not solver["changes"]):
        fail("manifest_solver_provenance")
    transition_names: set[str] = set()
    for change in solver["changes"]:
        if not isinstance(change, dict) or sorted(change) != ["action", "name", "previousVersion", "version"]:
            fail("manifest_transition_shape")
        action = change.get("action")
        name = change.get("name")
        previous = change.get("previousVersion")
        version = change.get("version")
        if (action not in {"install", "remove", "upgrade"}
                or not isinstance(name, str) or PACKAGE_PATTERN.fullmatch(name) is None
                or (previous is not None and (not isinstance(previous, str) or VERSION_PATTERN.fullmatch(previous) is None))
                or (version is not None and (not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None))):
            fail("manifest_transition")
        if ((action == "install" and (previous is not None or version is None))
                or (action == "remove" and (previous is None or version is not None))
                or (action == "upgrade" and (previous is None or version is None or previous == version))):
            fail(f"manifest_transition_fields package={name}")
        if name in transition_names:
            fail(f"manifest_transition_duplicate package={name}")
        transition_names.add(name)
        if action == "remove":
            if name in expected:
                fail(f"manifest_transition_final_presence package={name}")
        elif expected.get(name) != version:
            fail(f"manifest_transition_final_version package={name}")
    return architecture, expected


def canonical_package_name(name: str, architecture: str, known_names: set[str]) -> str:
    qualifier = package_architecture(name)
    if qualifier is not None:
        if qualifier != architecture:
            fail(f"foreign_architecture package={name}")
        return name
    candidates = [candidate for candidate in known_names if candidate == name or candidate.startswith(f"{name}:")]
    architecture_name = f"{name}:{architecture}"
    if architecture_name in candidates:
        return architecture_name
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        fail(f"ambiguous_multiarch package={name}")
    return name


def installed_package_map(architecture: str, expected_names: set[str]) -> dict[str, str]:
    result = run_command([
        "/usr/bin/dpkg-query",
        "--show",
        "--showformat=${binary:Package}\\t${db:Status-Abbrev}\\t${Version}\\n",
    ], timeout=30)
    if result.returncode != 0:
        fail("installed_inventory")
    installed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            fail("installed_inventory_format")
        raw_name, status, version = fields
        if re.fullmatch(r"[A-Za-z?]{2} ", status) is None:
            fail("installed_inventory_status")
        if status[1] != "i":
            continue
        name = canonical_package_name(raw_name, architecture, expected_names | set(installed))
        if name in installed:
            fail(f"installed_inventory_duplicate package={name}")
        installed[name] = version
    return installed


def parse_simulation(
    output: str,
    installed: dict[str, str],
    expected: dict[str, str],
    architecture: str,
    *,
    allow_existing_extras: bool = False,
) -> tuple[dict[str, str], set[str]]:
    final = dict(installed)
    known_names = set(installed) | set(expected)
    transitioned_names: set[str] = set()
    install_pattern = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+)(?: .*?)? \[([^\]]+)\]\)(?: .*|)$")
    remove_pattern = re.compile(r"^Remv (\S+)(?: \[([^\]]+)\])?(?: \[[^\]]*\])?")
    for line in output.splitlines():
        install = install_pattern.match(line)
        if install:
            raw_name, reported_previous, version, reported_architecture = install.groups()
            if reported_architecture not in {architecture, "all"}:
                fail(f"simulation_foreign_architecture package={raw_name}")
            name = canonical_package_name(raw_name, architecture, known_names)
            previous = final.get(name)
            if reported_previous is not None and previous != reported_previous:
                fail(f"simulation_previous_version package={name}")
            final[name] = version
            known_names.add(name)
            transitioned_names.add(name)
            continue
        remove = remove_pattern.fullmatch(line)
        if remove:
            raw_name, reported_previous = remove.groups()
            name = canonical_package_name(raw_name, architecture, known_names)
            previous = final.get(name)
            if previous is None or (reported_previous is not None and previous != reported_previous):
                fail(f"simulation_removal_version package={name}")
            del final[name]
            transitioned_names.add(name)
            continue
        if line.startswith("Inst") or line.startswith("Remv"):
            fail(f"simulation_unrecognized_transition line={line}")
    if not transitioned_names and final != expected and not allow_existing_extras:
        fail("simulation_missing_transitions")
    return final, transitioned_names


def compare_complete_package_map(final: dict[str, str], expected: dict[str, str]) -> None:
    unexpected = sorted(set(final) - set(expected))
    missing = sorted(set(expected) - set(final))
    changed = sorted(name for name in set(final) & set(expected) if final[name] != expected[name])
    if unexpected:
        fail(f"unexpected_packages packages={','.join(unexpected)}")
    if missing:
        fail(f"missing_packages packages={','.join(missing)}")
    if changed:
        details = ",".join(f"{name}={final[name]}!={expected[name]}" for name in changed)
        fail(f"unexpected_versions packages={details}")


def reject_existing_extras(installed: dict[str, str], expected: dict[str, str]) -> None:
    extras = sorted(set(installed) - set(expected))
    if extras:
        fail(f"unexpected_packages packages={','.join(extras)}")


def compare_map_preserving_extras(
    installed: dict[str, str],
    final: dict[str, str],
    expected: dict[str, str],
    transitioned_names: set[str],
) -> None:
    transitioned_extras = sorted(transitioned_names - set(expected))
    if transitioned_extras:
        fail(f"extra_package_transition packages={','.join(transitioned_extras)}")
    expected_with_extras = dict(expected)
    expected_with_extras.update({name: version for name, version in installed.items() if name not in expected})
    compare_complete_package_map(final, expected_with_extras)


def load_policy(encoded: str) -> dict[str, object]:
    try:
        decoded = base64.b64decode(encoded, validate=True)
        policy = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        fail("policy_invalid")
    if not isinstance(policy, dict) or sorted(policy) != ["keyrings", "manifest_sha256", "packages", "repositories"]:
        fail("policy_shape")
    if not all(isinstance(policy.get(key), list) for key in ["keyrings", "packages", "repositories"]):
        fail("policy_shape")
    manifest_sha256 = policy.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None:
        fail("policy_manifest_sha256")
    return policy


def load_manifest(path: Path, expected_sha256: str) -> object:
    try:
        if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
            fail("manifest_file")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            fail("manifest_checksum")
        return json.loads(content)
    except (OSError, json.JSONDecodeError):
        fail("manifest_invalid")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-base64", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--verify-installed-only", action="store_true")
    parser.add_argument("--allow-existing-extras", action="store_true")
    args = parser.parse_args()
    if args.verify_installed_only and args.allow_existing_extras:
        parser.error("--verify-installed-only requires an exact installed package map")
    policy = load_policy(args.policy_base64)
    architecture, expected = validate_manifest(load_manifest(args.manifest, policy["manifest_sha256"]))

    if args.verify_installed_only:
        compare_complete_package_map(installed_package_map(architecture, set(expected)), expected)
        print(
            f"apt_package_transaction=verified mode=installed-only selected=0 "
            f"installed={len(expected)} transitions=0 changed=false"
        )
        return

    selected: list[tuple[str, str]] = []
    for package in policy["packages"]:
        if not isinstance(package, dict):
            fail("selected_package_shape")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            fail("selected_package_type")
        resolved = canonical_package_name(name, architecture, set(expected))
        if resolved not in expected or expected[resolved] != version:
            fail(f"selected_package_manifest package={name}")
        selected.append((resolved, version))

    installed = installed_package_map(architecture, set(expected))
    if not args.allow_existing_extras:
        reject_existing_extras(installed, expected)

    with tempfile.TemporaryDirectory(prefix="home-lab-apt-transaction.") as temporary:
        root = Path(temporary)
        source_parts = root / "sources.list.d"
        config_parts = root / "apt.conf.d"
        lists = root / "lists"
        cache = root / "cache"
        log = root / "log"
        source_parts.mkdir(mode=0o700)
        config_parts.mkdir(mode=0o700)
        (lists / "partial").mkdir(parents=True, mode=0o700)
        (cache / "archives" / "partial").mkdir(parents=True, mode=0o700)
        log.mkdir(mode=0o700)

        keyrings = {str(item["path"]): verified_keyring(item, root) for item in policy["keyrings"]}
        for repository in policy["repositories"]:
            if not isinstance(repository, dict):
                fail("repository_shape")
            name = repository.get("name")
            if not isinstance(name, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]+", name) is None:
                fail("repository_name")
            signed_by_value = repository.get("signed_by")
            signed_by = keyrings.get(signed_by_value) if isinstance(signed_by_value, str) else None
            if signed_by is None:
                fail(f"repository_keyring name={name}")
            (source_parts / f"{name}.sources").write_text(render_source(repository, signed_by))

        check_options = apt_options(source_parts, config_parts, lists, cache, log, no_locking=True)
        apply_options = apt_options(source_parts, config_parts, lists, cache, log, no_locking=False)
        update = run_command(["/usr/bin/apt-get", *check_options, "update"])
        if update.returncode != 0:
            fail("metadata_refresh")

        unavailable: list[str] = []
        for name, version in selected:
            result = run_command(["/usr/bin/apt-cache", *check_options, "madison", name], timeout=30)
            versions = {
                fields[1].strip()
                for line in result.stdout.splitlines()
                if len(fields := line.split("|")) >= 3
            }
            if result.returncode != 0 or version not in versions:
                unavailable.append(f"{name}={version}")
        if unavailable:
            fail(f"versions_unavailable packages={','.join(unavailable)}")

        package_specs = [f"{name}={version}" for name, version in selected]
        simulation = run_command(transaction_command(check_options, package_specs, apply=False))
        if simulation.returncode != 0:
            fail("transaction_simulation")
        final, transitioned_names = parse_simulation(
            simulation.stdout,
            installed,
            expected,
            architecture,
            allow_existing_extras=args.allow_existing_extras,
        )
        if args.allow_existing_extras:
            compare_map_preserving_extras(installed, final, expected, transitioned_names)
        else:
            compare_complete_package_map(final, expected)

        changed = False
        if args.apply and transitioned_names:
            mutation = run_command(
                transaction_command(apply_options, package_specs, apply=True),
                timeout=APPLY_TIMEOUT_SECONDS,
            )
            if mutation.returncode != 0:
                fail("transaction_apply")
            changed = True
        if args.apply:
            applied = installed_package_map(architecture, set(expected) | set(installed))
            if args.allow_existing_extras:
                compare_map_preserving_extras(installed, applied, expected, set())
            else:
                compare_complete_package_map(applied, expected)

    print(
        f"apt_package_transaction=verified selected={len(selected)} installed={len(expected)} "
        f"transitions={len(transitioned_names)} changed={'true' if changed else 'false'}"
    )


if __name__ == "__main__":
    main()
