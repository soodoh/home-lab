# Outstanding work

This lists unresolved **decisions**, not migration receipts. Reobserve the host,
remote state, provider and backup repositories before acting; Git history is not
proof of current state.

## Vikunja to Mindwtr access and acceptance

`todo.diloreto.com` still serves Vikunja; Mindwtr is staged, not the live route.
For cutover, gate Mindwtr's web app with Authentik. Route `/v1/*` to Mindwtr
Cloud without web forward-auth so native sync clients can use their separate,
fixed Cloud token. Do **not** require that token on every Cloud URL: a calendar
feed explicitly created through the authenticated API uses its own revocable
URL bearer token at `/v1/calendar/<token>.ics`. Blocking this path breaks
calendar subscriptions. Treat feed URLs as secrets; test that an unknown or
revoked feed token cannot retrieve task data. Authentik does not authenticate
calendar subscribers or replace Cloud's token authentication.

Before switching the route, reobserve source and backups, freeze Vikunja
writes, convert a fresh protected export, reconcile the incomplete tasks and
review the import. Require hands-on acceptance after cutover. Vikunja service,
OIDC resources, secrets and active data remain until **separate explicit
approval** for their destructive retirement. Keep one-off exports and receipts
outside Git; remove this section after the transition is complete.

## AWS recovery-key and separate backup identity

The recovery KMS key was scheduled for deletion under independent AWS owner
custody. Verify its **current** state and dependencies with that owner. Keep the
independently owned `s3-backup-user` and inactive key until AWS confirms final
key deletion and a separately approved owner cutover confirms no consumers.
Do not infer nonuse from IAM last-used timestamps, a single host, or a past
bucket inventory. Before changing this identity, verify independent custody of
required encrypted recovery material and a fresh private restore; privately
review its policy attachments and all consumers. Only the independent owner
may approve credential revocation, policy detachment or deletion. Preserve
protected state versions and any nonterminal owner records outside Git.

## Recovery activation

[Recovery](../recovery/README.md) supports fresh snapshot discovery and verified
private staging, **not** production data activation. A reusable activation
procedure must define writer exclusion, database validation, external storage,
before-images, rollback and post-activation health before production restore.

## Deferred ingress qualifications

Actual ephemeral CI/application access, isolated authenticated GOST destination
denials (without a client-side bypass), and private-route UDP/HTTP3 negatives
were not qualified as part of the prior ingress change. Test these against
fresh live state before relying on those boundaries. System PAC on the work Mac
is off; its reported CLIProxyAPI/Omada access is not a browser-path test.
