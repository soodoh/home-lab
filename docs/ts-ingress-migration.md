# Tailnet Traefik ingress migration (proposal; not deployment approval)

Goal: replace the Docker host's Tailscale Serve routes with
`https://omada.ts.diloreto.com` and `https://llm.ts.diloreto.com`, with no
explicit client port. CI and local controllers may reach both. Public direct
access must remain impossible. The work Mac may reach **only** the LLM hostname
through the existing public, Authentik-authenticated GOST relay; that is a
separate authenticated exception, not a claim that every caller is a tailnet
member.

This document is a staged design, not permission to apply a plan, alter an
AWS identity boundary, reset Serve, or converge Compose. Use
[operations](operations.md) for fresh host/provider observations, protected
plans, backup admission, locks, rollback access, and check-mode gates.

## Observed design constraints

- The public Traefik instance already receives Omada WAN 80/443 via host
  18080/18443. Preserve those forwards and its explicit public host allowlist.
  The shared `*.diloreto.com` DNS CNAME currently also answers names below
  `ts.diloreto.com`; a more specific `*.ts.diloreto.com` record must override it.
  Verify the authoritative hosted-zone records before managing one in OpenTofu.
- Serve owns both current tailnet routes (`:8443` Omada and `:8444`
  CLIProxyAPI). Its Ansible role runs **before** Compose convergence in
  `site.yml`, so removing Serve in the same first deployment as its replacement
  could interrupt Omada provider access. Keep Serve during the new ingress
  rollout and client migration; retire it in a separate convergence.
- Omada publishes HTTPS on host `127.0.0.1:8043` with a private-CA certificate;
  CLIProxyAPI publishes HTTP on `127.0.0.1:8317`. A private Traefik instance
  using host networking can proxy both loopback listeners, keeping the Omada
  backend TLS exception on an encrypted **loopback** hop only. Verify that no
  other listener claims the Docker host's Tailscale IPv4 on TCP 443. Bind the
  private instance explicitly to that IP; do not use `:443`/all interfaces or
  forward this port through Omada. Observe the node identity/IP immediately
  before convergence and refuse mismatch with the reviewed address. Revisit the
  binding if the node is re-enrolled and its Tailscale IP changes.
- Two Traefik instances need separate static/dynamic configurations, ACME
  stores and DNS credentials. The private instance requests a certificate for
  `*.ts.diloreto.com` via Route 53 DNS-01. It needs **only** explicit routers
  for the approved hosts, not a catch-all wildcard backend. Existing public
  Traefik keeps HTTP-01 and must never load the private routes. Neither proxy
  needs Docker socket access. The private ACME store and credentials require
  root-owned protected files and independent recovery/renewal checks.
- Tailscale grants can permit owner/admin and CI to Docker-host TCP 443. That
  exposes both routes at the network layer to CI; Omada login, CLIProxyAPI API
  key, and distinct full-privilege management key remain required. Keep the old
  grants until clients have migrated; remove `8443`/`8444` after Serve retirement.
  Decide separately whether direct Omada TCP 8043 is still needed for owners.
- GOST's existing `*.mora-rattlesnake.ts.net` any-port matcher is broader than
  this use case. After migrating the work-Mac client, replace it with the exact
  `llm.ts.diloreto.com:443` destination, retain only the required Tailscale
  control-plane destinations, and test the **remote** whitelist. GOST reaches
  the private ingress using the Docker host's network identity; a client with
  the relay app password can CONNECT without being on the tailnet. That
  password is an ingress credential, not an API key. Do not call this path
  tailnet-only or unauthenticated. Check GOST DNS resolution of the new record,
  including resolver rebinding behavior, from inside its container.
- The Proxmox *cluster* firewall protects Proxmox, not this Docker-host
  listener. Do not change it merely for this ingress; verify the actual Docker
  VM/host firewall, Tailscale grants and Docker port/network behavior.

## AWS ownership blocker: separate security change first

`aws-foundation` does not own the public hosted zone or DNS records. Its
controller roles have external owner-controlled permissions boundaries, and
`infrastructure/policy/inspect-plan.py` refuses managed IAM/Roles Anywhere
mutations **by default**. A proposed, plan-bound exception now permits only
exactly approved creation of this ACME user/policy/attachment and updates to
the two named controller IAM policies. OpenTofu now declares those resources,
but the exception alone does not provision an identity or credential.
Neither a normal allowlist nor an exact-plan deletion approval overrides the
identity gate. Do not add IAM users/keys/policies to a
normal AWS plan or broaden the existing DDNS credential. The previous Route 53
key is still used by live DDNS; do not rotate or revoke it incidentally.

The owner chose to redesign the IAM gate rather than manually provision the
ACME identity. Treat this as an independently reviewed security migration:

1. Agree with the independent AWS owner on a *new*, dedicated ACME identity,
   its credential custody/rotation and exact least-privilege policy. Limit
   `ChangeResourceRecordSets` to TXT for
   `_acme-challenge.ts.diloreto.com` in the verified hosted zone; allow only
   the provider-required zone-read/change-status calls. Do not put an access
   key secret in OpenTofu state, the repo or an image. If key issuance remains
   manual, document precisely which identity resources OpenTofu owns.
2. Review changes to the external plan/apply role permissions boundaries, the
   controller's own IAM policies and the inspector as **one ownership
   protocol**, not merely an `aws_iam_*` address allowlist. The proposed
   inspector exception requires the verified root, resource type/address,
   create/update-only operation, expected identity name and known fields,
   complete drift-free plan and private exact-plan owner authorization. The
   owner must independently review the full policy document: an exact-plan
   approval does not itself prove least privilege. Retain absolute
   OIDC prohibition, unrelated IAM mutation/drift/refusal, unknown/deferred
   result denial, and deletion/import safeguards. Prove the exception and
   negative cases with synthetic plan-policy tests before a live plan.
3. Separately review and enact the owner-controlled boundary change. The
   current apply role cannot update its own IAM permissions: owner bootstrap
   and separately reviewed state reconciliation are necessary before any
   normal plan can pass. The independent owner must also supply the verified
   existing public-zone ID (`TF_VAR_tail_ingress_zone_id`) and separately
   owned ACME-user permissions boundary ARN
   (`TF_VAR_tail_ingress_user_boundary_arn`). Compare the public-zone data
   lookup and the reviewed `tail-ingress.auto.tfvars.json` IPv4 to fresh
   authoritative provider and node observations, and inspect whether the
   exact wildcard DNS record already exists before planning any creation.
   Then inspect a fresh `aws-foundation` saved plan under the newly reviewed
   policy and explicitly approve the exact IAM changes. Do not weaken the default gate
   merely to obtain a passing plan. Adopt/import existing resources only with
   verified identity and separately approved owner procedure; never silently
   overwrite a DNS record. Require a fresh no-op plan after apply.
4. Put only the issued scoped credential in protected SOPS-backed deployment
   material, render it root-only at runtime, and test DNS-01 with a staging CA
   before production issuance. Never print decrypted Compose output, the ACME
   store, provider state or plan JSON.

The first code change should be this **policy/identity ownership review**, not
removal of Serve. If the owner cannot approve the revised IAM policy/boundary,
stop and reconsider independent owner provisioning rather than bypass the gate.

## Ordered deployment after AWS approval

1. Confirm current host/Compose/backup observations, the tailnet IPv4,
   authoritative Route 53 zone/record ownership, independent console access,
   and absence of host port conflicts. Manage the specific
   `*.ts.diloreto.com` A record with OpenTofu and verify that authorized
   clients resolve it to the observed Docker-host Tailscale IP; test actual
   client resolvers for private-address rebinding protection. No public DNS
   record is an authorization boundary.
2. Add private Traefik as a separate host-network service. Bind only the
   reviewed Tailscale IP on TCP 443. Configure explicit Omada and LLM routers,
   DNS-01, distinct protected ACME state and scoped AWS credentials. Keep the
   public Traefik untouched and Serve active. Verify Omada API authentication
   and CLIProxyAPI management/API-key paths with strict client TLS. An Omada
   backend TLS exception must remain confined to `127.0.0.1:8043`.
3. Change Tailscale grants to permit owner/admin and CI on Docker-host TCP
   443; test both routes from owner and CI, and an unauthorized tailnet source.
   From outside the LAN, force each `*.ts.diloreto.com` hostname to the public
   IP and verify no application route; test from the LAN and against both WAN
   forwards. Test GOST's exact CONNECT allowance, strict TLS, and refusal of
   Omada/other tailnet destinations with a client lacking local bypasses.
4. Move the Omada OpenTofu provider URL, protected export helper, local and CI
   controllers, work-Mac client, site health checks and GOST whitelist to the
   new names. Verify a fresh Omada export/plan and real work-Mac request before
   treating old endpoints as unused. The work-Mac dotfiles are a separate
   authority; coordinate their rollout without breaking its Tailscale control
   proxy. Update security, operations, deployment-access and architecture docs.
5. Only then remove the Serve role/play and reset **only its observed owned
   node-level config**, drop the `8443`/`8444` grants and check that both old
   routes are closed. Do not remove Omada loopback or CLIProxyAPI loopback
   publications if the new host-network Traefik still uses them. Reobserve
   Compose, backups and provider state; keep independent rollback access and
   preserved before-images until the new route is qualified.
