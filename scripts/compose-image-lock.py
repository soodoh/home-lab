#!/usr/bin/env python3
"""Capture and verify current/previous Compose images before destructive pruning."""

from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


def fail(reason: str) -> None:
    print(f"compose_image_lock=failed reason={reason}", file=sys.stderr)
    raise SystemExit(1)


def docker_json(arguments: list[str]) -> Any:
    try:
        result = subprocess.run(
            ["docker", *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        fail("docker_inspection_error")


def capture(args: Namespace) -> None:
    try:
        containers = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--quiet",
                "--filter",
                f"label=com.docker.compose.project={args.project}",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.splitlines()
    except subprocess.SubprocessError:
        fail("container_inventory_error")

    images: dict[str, dict[str, Any]] = {}
    if containers:
        inspected = docker_json(["inspect", *containers])
        for container in inspected:
            labels = container.get("Config", {}).get("Labels", {}) or {}
            service = labels.get("com.docker.compose.service")
            image_id = container.get("Image")
            reference = container.get("Config", {}).get("Image")
            if not service or not image_id or not reference:
                fail("compose_identity_missing")
            if service in images:
                fail("duplicate_compose_service")
            image = docker_json(["image", "inspect", image_id])[0]
            images[service] = {
                "service": service,
                "reference": reference,
                "image_id": image_id,
                "repo_digests": sorted(image.get("RepoDigests") or []),
            }

    document = {
        "schema": 1,
        "project": args.project,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "images": [images[name] for name in sorted(images)],
    }
    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile("w", dir=output.parent, delete=False) as stream:
        json.dump(document, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.chmod(0o600)
    temporary.replace(output)
    print(f"compose_image_lock=captured services={len(images)}")


def read_lock(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(f"{label}_lock_unreadable")
    if document.get("schema") != 1 or not isinstance(document.get("images"), list):
        fail(f"{label}_lock_schema")
    return document["images"]


def verify(args: Namespace) -> None:
    current = read_lock(args.current, "current")
    previous = read_lock(args.previous, "previous")
    if not current:
        fail("current_lock_empty")
    if not previous:
        fail("previous_lock_empty")

    checked_ids: set[str] = set()
    checked_digests: set[str] = set()
    for lock_name, records in (("current", current), ("previous", previous)):
        services: set[str] = set()
        for record in records:
            service = record.get("service")
            image_id = record.get("image_id")
            digests = record.get("repo_digests")
            if (
                not isinstance(service, str)
                or not isinstance(image_id, str)
                or not image_id.startswith("sha256:")
                or not isinstance(digests, list)
                or not digests
            ):
                fail(f"{lock_name}_record_schema")
            if service in services:
                fail(f"{lock_name}_duplicate_service")
            services.add(service)
            if image_id not in checked_ids:
                docker_json(["image", "inspect", image_id])
                checked_ids.add(image_id)
            for digest in digests:
                if not isinstance(digest, str) or "@sha256:" not in digest:
                    fail(f"{lock_name}_digest_schema")
                if args.check_registry and digest not in checked_digests:
                    try:
                        subprocess.run(
                            ["docker", "manifest", "inspect", digest],
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    except subprocess.SubprocessError:
                        fail("registry_digest_unavailable")
                    checked_digests.add(digest)

    print(
        "compose_image_lock=verified "
        f"current_services={len(current)} previous_services={len(previous)} "
        f"local_images={len(checked_ids)} registry_digests={len(checked_digests)}"
    )


def activate(args: Namespace) -> None:
    records = read_lock(args.lock, "activation")
    activated = 0
    for record in records:
        reference = record.get("reference")
        image_id = record.get("image_id")
        if (
            not isinstance(reference, str)
            or not reference
            or not isinstance(image_id, str)
            or not image_id.startswith("sha256:")
        ):
            fail("activation_record_schema")
        docker_json(["image", "inspect", image_id])
        if "@sha256:" in reference:
            continue
        try:
            subprocess.run(
                ["docker", "image", "tag", image_id, reference],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.SubprocessError:
            fail("rollback_reference_activation_error")
        activated += 1
    print(f"compose_image_lock=activated references={activated}")


def difference(args: Namespace) -> None:
    current = {record["service"]: record for record in read_lock(args.current, "current")}
    previous = {record["service"]: record for record in read_lock(args.previous, "previous")}
    removed = set(current) - set(previous)
    added = set(previous) - set(current)
    if removed or added:
        if args.allow_removed_service is None or removed != {args.allow_removed_service} or added:
            fail("image_lock_service_set_changed")
    changed = sorted(
        service
        for service in set(current) & set(previous)
        if current[service].get("image_id") != previous[service].get("image_id")
    )
    print(json.dumps(changed, separators=(",", ":")))


def prune(args: Namespace) -> None:
    verify(args)
    records = read_lock(args.current, "current") + read_lock(args.previous, "previous")
    image_ids = sorted({record["image_id"] for record in records})
    protection_containers: list[str] = []
    try:
        for index, image_id in enumerate(image_ids):
            result = subprocess.run(
                [
                    "docker",
                    "create",
                    "--label",
                    "home-lab.prune-protection=true",
                    "--name",
                    f"home-lab-prune-protection-{index}",
                    image_id,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            protection_containers.append(result.stdout.strip())
        subprocess.run(
            ["docker", "image", "prune", "--all", "--force", "--filter", f"until={args.until}"],
            check=True,
        )
    except subprocess.SubprocessError:
        fail("protected_image_prune_error")
    finally:
        if protection_containers:
            subprocess.run(
                ["docker", "container", "rm", "--force", *protection_containers],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    print(f"compose_image_lock=pruned protected_images={len(image_ids)}")

def review_generations(generations: dict, project: str, old: dict, new: dict, transition: object) -> dict:
    """Independent synthetic generation associations, never registry or recovery proof.

    Each model is a secret-free supplied declaration map, not a rendered Compose model.
    Retention overlays are subsets; they never supply defaults for another generation.
    Legacy capture/activation/registry/prune functions are not part of this pure route.
    """
    import hashlib
    import importlib.util
    import re
    spec = importlib.util.spec_from_file_location('compose_artifact_images', Path(__file__).with_name('compose-artifact.py'))
    artifact = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(artifact)
    def digest(item):
        return hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    def token(item):
        return isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,239}', item) is not None
    def image_id(item):
        return isinstance(item, str) and re.fullmatch('sha256:[0-9a-f]{64}', item) is not None
    blockers = set(); names = set(); inventories = {}; platforms = {}
    for side in ('current', 'candidate', 'previous'):
        generation = generations[side]
        if (not isinstance(generation, dict) or set(generation) != {'generation', 'manifest', 'environment',
                'model', 'model_sha256', 'images', 'override'} or not token(generation['generation'])
                or generation['generation'] in names):
            raise ValueError('invalid or aliased image generation')
        names.add(generation['generation'])
        artifact.validate_manifest(generation['manifest'])
        if ((side == 'current' and generation['manifest'] != old)
                or (side == 'candidate' and generation['manifest'] != new)):
            raise ValueError('image generation manifest association mismatch')
        environment = generation['environment']
        if (not isinstance(environment, dict) or set(environment) != {'generation', 'protected_sha256'}
                or not token(environment['generation']) or not isinstance(environment['protected_sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', environment['protected_sha256'])):
            raise ValueError('invalid independent environment association')
        model = generation['model']
        if (not isinstance(model, dict) or set(model) != {'project', 'services'} or model['project'] != project
                or not isinstance(model['services'], dict) or len(model['services']) > 256
                or generation['model_sha256'] != digest(model)
                or any(not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', name) or not token(ref)
                       for name, ref in model['services'].items())):
            raise ValueError('invalid generation model content association')
        rows = generation['images']; override = generation['override']
        if (not isinstance(rows, list) or len(rows) > 256 or not isinstance(override, dict)
                or not set(override) <= set(model['services'])):
            raise ValueError('invalid image inventory or subset membership')
        images = {}
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {'service', 'declaration', 'reference', 'image_id',
                    'platform', 'repo_digests', 'available', 'retained'}
                    or not isinstance(row['service'], str) or row['service'] not in model['services']
                    or row['declaration'] != model['services'][row['service']] or not token(row['reference'])
                    or not image_id(row['image_id']) or not isinstance(row['platform'], str)
                    or not re.fullmatch('[a-z0-9]+/[a-z0-9]+(?:/[a-z0-9]+)?', row['platform'])
                    or type(row['available']) is not bool or not isinstance(row['repo_digests'], list)
                    or len(row['repo_digests']) > 128
                    or any(not isinstance(d, str) or len(d) > 320 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]*@sha256:[0-9a-f]{64}', d)
                           for d in row['repo_digests']) or len(set(row['repo_digests'])) != len(row['repo_digests'])):
                raise ValueError('invalid image declaration or immutable identity')
            service = row['service']
            if service in images:
                raise ValueError('duplicate image service identity')
            images[service] = row
            if row['image_id'] in platforms and platforms[row['image_id']] != row['platform']:
                raise ValueError('inconsistent immutable image platform')
            platforms[row['image_id']] = row['platform']
            if not row['available']:
                blockers.add(side + ':image-preparation-required:' + service)
            retained = {'generation': generation['generation'], 'service': service,
                        'declaration': row['declaration'], 'reference': row['reference'], 'image_id': row['image_id']}
            if row['retained'] is not None and row['retained'] != retained:
                raise ValueError('invalid local retention content association')
            if not row['repo_digests'] and row['retained'] is None:
                blockers.add(side + ':local-retention-provenance-required:' + service)
        if set(images) != set(model['services']):
            raise ValueError('incomplete independent generation image inventory')
        for service, row in override.items():
            if (not isinstance(row, dict) or set(row) != {'declaration', 'reference', 'image_id'}
                    or not token(row['declaration']) or not token(row['reference']) or not image_id(row['image_id'])
                    or row['reference'] != images[service]['reference'] or row['image_id'] != images[service]['image_id']
                    or (side != 'candidate' and row['declaration'] != images[service]['declaration'])):
                raise ValueError('invalid subset image association')
        for service, row in images.items():
            if service not in override and row['reference'] != row['declaration']:
                blockers.add(side + ':effective-reference-association-required:' + service)
        inventories[side] = images
    changes = []
    current, candidate = inventories['current'], inventories['candidate']
    old_override, new_override = generations['current']['override'], generations['candidate']['override']
    for service in sorted(set(current) | set(candidate)):
        before, after = current.get(service), candidate.get(service)
        before_identity = {k: before[k] for k in ('declaration', 'reference', 'image_id')} if before else None
        after_identity = {k: after[k] for k in ('declaration', 'reference', 'image_id')} if after else None
        declaration_changed = before is None or after is None or before['declaration'] != after['declaration']
        id_changed = before is None or after is None or before['image_id'] != after['image_id']
        reference_changed = before is None or after is None or before['reference'] != after['reference']
        if before_identity != after_identity:
            changes.append({'service': service, 'old': before_identity, 'new': after_identity,
                            'declaration_changed': declaration_changed, 'reference_changed': reference_changed,
                            'effective_id_changed': id_changed})
            blockers.add('image-transition-review-required:' + service)
        if before and after and not declaration_changed and id_changed:
            blockers.add('moving-tag-or-implicit-refresh:' + service)
        if (service in new_override and after and new_override[service]['declaration'] != after['declaration']):
            if service not in old_override or new_override[service] != old_override[service]:
                raise ValueError('candidate hold has no current subset association')
            blockers.add('hold-masks-declaration-change:' + service)
    if old_override != new_override:
        blockers.add('subset-transition-proposal-required')
    if transition is not None:
        changed_members = {s for s in set(old_override) | set(new_override)
                           if old_override.get(s) != new_override.get(s)}
        changed_images = {row['service']: row for row in changes}
        if (not isinstance(transition, dict) or set(transition) != {'status', 'old_override', 'new_override', 'services'}
                or transition['status'] != 'proposed' or transition['old_override'] != old_override
                or transition['new_override'] != new_override or not changed_members
                or not changed_members <= set(changed_images) or not isinstance(transition['services'], list)
                or len(transition['services']) != len(changed_members)):
            raise ValueError('invalid exact subset transition proposal')
        proposed = set()
        for row in transition['services']:
            if (not isinstance(row, dict) or set(row) != {'service', 'old', 'new'}
                    or not isinstance(row['service'], str) or row['service'] not in changed_members
                    or row['service'] in proposed):
                raise ValueError('invalid affected subset service set')
            service = row['service']; change = changed_images[service]
            if row['old'] != change['old'] or row['new'] != change['new']:
                raise ValueError('subset transition image association mismatch')
            if service in candidate and (service not in new_override or new_override[service] != change['new']):
                raise ValueError('subset transition may not silently lift an existing hold')
            proposed.add(service)
        blockers.discard('subset-transition-proposal-required')
        blockers.add('subset-transition-proposed-not-approved')
    return {'generations': generations, 'generation_sha256': {k: digest(v) for k, v in generations.items()},
            'changes': changes, 'transition': transition, 'blockers': sorted(blockers),
            'recovery_certified': False, 'data_reversible': False}


def main() -> None:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--project", default="docker-compose")
    capture_parser.set_defaults(handler=capture)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--current", type=Path, required=True)
    verify_parser.add_argument("--previous", type=Path, required=True)
    verify_parser.add_argument("--check-registry", action="store_true")
    verify_parser.set_defaults(handler=verify)

    activate_parser = subparsers.add_parser("activate")
    activate_parser.add_argument("--lock", type=Path, required=True)
    activate_parser.set_defaults(handler=activate)

    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("--current", type=Path, required=True)
    diff_parser.add_argument("--previous", type=Path, required=True)
    diff_parser.add_argument("--allow-removed-service")
    diff_parser.set_defaults(handler=difference)

    prune_parser = subparsers.add_parser("prune")
    prune_parser.add_argument("--current", type=Path, required=True)
    prune_parser.add_argument("--previous", type=Path, required=True)
    prune_parser.add_argument("--check-registry", action="store_true")
    prune_parser.add_argument("--until", default="168h")
    prune_parser.set_defaults(handler=prune)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
