# Compose generation activation

## Authoritative native site

`ansible/playbooks/site.yml` is the normal Docker-host convergence interface. It uses
the native `docker-host` inventory, re-observes live coordination and Compose state,
acquires production ownership, converges the adopted Restic runtime, installs Docker
maintenance, publishes the tracked Compose artifact, removes retired Compose recovery
state, releases ownership and performs a final observation. Check mode performs no
host mutation.

The site derives the exact clean controller commit, complete declared service set,
selected artifact differences and changed bind-file owners. Operators do not provide
service lists, changed-path lists, artifact hashes or source commits for ordinary
convergence. `deploy-compose.yml` remains a lower-level bounded entrypoint for an
explicitly reviewed service subset; it is not the normal site interface.

The prepared `compose_native_generation` mapping contains only:

- the operation and exact candidate/current artifact hashes;
- transaction candidate artifact/environment paths;
- requested and forced-recreation service sets;
- whether the caller intentionally isolates dependencies; and
- the complete expected service set/count and required healthy containers.

It contains no image lock or checkpoint. Tracked repository digest references are the
sole image authority. Missing requested images use `policy: missing`; all previews and
convergence use `pull: never`. Authoritative site convergence includes dependencies
and lets native Compose recreate only resolved-model changes. Exact changed bind-file
owners use forced recreation. A bounded isolated caller may require the guarded
Compose 2.26 recreate/start settlement pass.

## Publication and rollback

The deterministic artifact is staged only for the active transaction. Publication
moves the live artifact/environment to hash-bound hidden before-images, atomically
publishes the candidate, converges and verifies the complete project, advances the
active artifact marker, then removes the consumed before-images and candidate inputs.
A failure retains its transaction-local before-images and production owner for an
exact inspected forward recovery. There are no standing `previous` pointers or
hash-addressed rollback archives.

Ordinary rollback is an authoritative forward deployment of a reviewed Git revert
commit using the latest automation. Missing old images may be pulled by exact digest;
registry/network availability is accepted. There is no old-artifact or local-image-ID
activation interface.

## Generic disaster recovery

Compose-specific migration rollback, old archive activation, staging/review roles,
`compose-action-plan.py` and `compose-image-lock.py` are retired. The only supported
data-disaster path is the generic Restic bundle/restore flow documented in
[`recovery/README.md`](../recovery/README.md).

`recovery/groups.json` declares stateful recovery groups. The generic restore runner
accepts all groups or repeated group selections and restores the exact selected paths
plus common protected environment input into private staging. Group selection does
not weaken repository, snapshot, policy, artifact, binary, target or verification
gates. Production activation remains unqualified until a generic group-driven
activation module passes isolated Gate 2 qualification.

## Docker image maintenance

The native site owns `home-lab-docker-image-prune.timer`. It runs weekly on Sunday at
04:00 with a persistent timer and randomized delay. Its helper coordinates through
the existing backup mutex, reconciliation locks and durable production owner, then
runs only:

```text
docker image prune --all --force --filter until=168h
```

It never prunes volumes. Docker preserves images referenced by containers; an unused
historical image may later require an exact-digest pull. A prune failure retains its
production owner for diagnosis.

## Safety limits

The authoritative site still refuses:

- dirty controller source;
- mutable image references;
- service additions/removals or protected topology changes;
- top-level network, volume, config or secret changes;
- unapproved plaintext environment drift;
- unavailable backup coordination or retained operation ownership; and
- any nonzero final full-project preview.

Database migrations, storage replacement, file-backed secret publication, generic
Restic production activation and Proxmox provider changes remain separate operations.
