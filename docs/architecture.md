# Architecture and authority

## Sources of truth

| Concern | Authority |
| --- | --- |
| Desired resources and host configuration | Reviewed Git source |
| Current host and application state | Fresh Proxmox/Docker-host observation |
| Current provider state | Fresh provider reads and plans |
| Provider-resource ownership | OpenTofu remote state |
| Active mutation or recovery | Host-local lock, journal and before-image |
| Secrets and recovery payloads | SOPS or independent protected storage |
| Historical explanation | Git, review and CI history |

Observation output is transient. It may authorize only the run that produced it,
and mutation must revalidate relevant conditions after acquiring ownership.

## Boundaries

### Git

Git contains declarative configuration, version/digest pins, policy, schemas for
reusable interfaces, and synthetic tests. It does not contain saved plans, state,
receipts, historical observations or completed transaction records.

A digest in Git identifies desired bytes. It does not prove those bytes are live.

### Controllers

A controller checkout and its caches are disposable. A valid workflow works from a
fresh clone with current credentials and network access. `.local/`, `.reconcile/`,
provider caches and captured browser output are never inputs to another run.

### Managed hosts

A host may retain state needed to make an interrupted mutation safe. A nonterminal
owner, journal or before-image remains authoritative until an operator observes and
resolves it. Terminal records receive bounded retention and are not copied into Git.

### OpenTofu

Every active provider root uses a remote backend. Planning refreshes that state
against the provider. Saved plans are short-lived private files bound to one reviewed
run; they are destroyed after apply, refusal or abandonment.

### Recovery

Git defines recovery groups and recovery tooling. Snapshot IDs, repository IDs,
current artifact identities and tool identities are discovered live. Recovery
credentials and encrypted bundles live outside Git.

## Durable design decisions

- The existing hosts are adopted through standard SSH and Ansible privilege
  escalation; there is no custom controller state machine.
- Compose convergence is generation-based and source-bound. Git revert followed by
  convergence is configuration rollback.
- Data recovery stages into a new private directory before any production decision.
- External Nextcloud user data is outside the managed Restic recovery group and must
  be handled independently.
- Host-side autonomous rollback may outlive a controller only where loss of
  connectivity could otherwise strand the host.
