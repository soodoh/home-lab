# Tailnet Traefik ingress migration (completed; historical design and outcome)

Goal: replace the Docker host's Tailscale Serve routes with
`https://omada.ts.diloreto.com` and `https://llm.ts.diloreto.com`, with no
explicit client port. CI and local controllers may reach both. Public direct
access must remain impossible. The work Mac has an authenticated GOST
exception for **both** private subdomains on TCP 443; that is not a claim that every caller is a tailnet
member. Serve was retired on 2026-09-27, with actual CI, remote GOST denials
and UDP/HTTP3 explicitly waived rather than proven.

This document records the staged design and completed steps; it is not
permission to replay a plan, alter an AWS identity boundary, restore/reset
Serve, or converge Compose. Use
[operations](operations.md) for fresh host/provider observations, protected
plans, backup admission, locks, rollback access, and check-mode gates.

## Observed design constraints

- The public Traefik instance already receives Omada WAN 80/443 via host
  18080/18443. Preserve those forwards and its explicit public host allowlist.
  The shared `*.diloreto.com` DNS CNAME currently also answers names below
  `ts.diloreto.com`; a more specific `*.ts.diloreto.com` record must override it.
  Verify the authoritative hosted-zone records before managing one in OpenTofu.
- At the initial stage, Serve owned both tailnet routes (`:8443` Omada and
  `:8444` CLIProxyAPI). Its Ansible role runs **before** Compose convergence in
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
- The approved host convergence replaced GOST's any-port
  `*.mora-rattlesnake.ts.net` matcher with `*.ts.diloreto.com:443`, retaining
  Tailscale control-plane destinations. The separately committed work-Mac
  client was later deployed by the operator and positively reported. The new
  allowance includes Omada and LLM; each route needs its own application
  credentials, and future services need
  explicit private Traefik routers and appropriate Authentik protection where
  intended. GOST reaches private ingress using the Docker host's network
  identity; a holder of the relay app password can CONNECT from off-tailnet.
  That password is an ingress credential, not an API key. Do not call this
  path tailnet-only or unauthenticated. DNS and TCP 443 from the GOST container
  passed; authenticated CONNECT and denied-target checks remain pending.
- The Proxmox *cluster* firewall protects Proxmox, not this Docker-host
  listener. Do not change it merely for this ingress; verify the actual Docker
  VM/host firewall, Tailscale grants and Docker port/network behavior.

## AWS ownership stage: reviewed bootstrap complete; production TLS deployed

`aws-foundation` does not own the public hosted zone; it now owns only the exact
`*.ts.diloreto.com` A record in that zone. Its
controller roles have external owner-controlled permissions boundaries, and
`infrastructure/policy/inspect-plan.py` refuses managed IAM/Roles Anywhere
mutations **by default**. A plan-bound exception permitted only the
independently approved creation of this ACME user/policy/attachment. Controller
plan/apply IAM policy changes remain owner-only, including the initial
bootstrap of the narrower DNS permissions. OpenTofu declares the identity,
but the exception alone does not provision it or its credential.
Neither a normal allowlist nor an exact-plan deletion approval overrides the
identity gate. Do not add IAM users/keys/policies to a
normal AWS plan or broaden the existing DDNS credential. The previous Route 53
key is still used by live DDNS; do not rotate or revoke it incidentally.
The owner bootstrap, exact wildcard record and ACME IAM resources are live,
with a fresh drift-free, no-change `aws-foundation` plan. A failed Route 53
synchronization poll required separate state recovery and a scoped controller
`GetChange` owner correction; both were independently reviewed. The ACME user
now has one scoped access key encrypted in `secrets/production.sops.yaml`.
A separately approved host convergence deployed staging, followed by another
approval to issue a production Let's Encrypt wildcard into a separate protected
store. Serve is unchanged. Both explicit routes answered over host-local strict
TLS with the trusted production certificate, and an unlisted route returned
404. The staging certificate store remains for rollback. A separately approved
manual native backup cycle produced a complete, admitted chain for the new
production-CA artifact. A separately approved exact Tailscale saved plan added
owner/admin and CI grants to Docker-host TCP 443, retaining old Serve ports.
The owner controller reached both private routes with strict TLS, while a
`tag:proxmox` source timed out; provider policy tests and a fresh no-change
plan passed. The local Omada provider/export source now uses the new hostname:
authenticated exports through Serve and private Traefik returned identical
managed state, and a fresh new-route Omada plan had zero actions and no drift.
The operator reports off-tailnet access blocked; actual CI access is explicitly
deferred, not proven. The approved `b6e04a49` host site convergence narrowed
the live GOST matcher to `*.ts.diloreto.com:443` and retained all 42 Compose
services. Strict TLS, explicit private routers, Serve and the running config
checksum passed after apply. The operator reports that dotfiles commit
`e9c745f` on the actual work Mac passed strict-TLS LLM access, a real API-key
request, Omada login and Tailscale coordination. System PAC remains off;
browser access and the remote server's denied-target boundary are unverified.
The TCP network negatives passed on 2026-09-27: `tag:proxmox` timed out on
both private routes, direct Docker-host LAN-IP:443 timed out, and forced-public-IP
probes from both LAN hairpin and an independent cellular hotspot returned 301
on WAN port 80 and 404 on WAN port 443 for both private hostnames. The cellular
client's public egress differed from the home WAN IP and its route did not use
Tailscale. UDP/HTTP3 was not separately exercised. A post-GOST-apply backup
observation initially refused with `complete_chain_missing`. A later native
manual backup completed and the observer admitted the current Compose artifact
before Serve retirement. The operator accepted residual risk from actual CI,
isolated GOST denial and UDP/HTTP3 checks remaining unverified; no verification
success may be inferred from that waiver.

On 2026-09-27, committed source `ab9442e2` and passing focused/site check modes
preceded the focused host reset of exactly the two owned node-level Serve
routes. A protected before-image was captured; both loopback backends stayed.
Strict-TLS Omada returned 200, unauthenticated LLM 401 and an unlisted private
host 404. The operator approved and applied the exact saved Tailscale plan
SHA-256 `a8433c4e24e767d52e55f6d6a72857ae378005a93d122b8d59d82f612d14f5d5`:
it removed only the two old port grants, not TCP 443 or SSH. A fresh provider
plan had no changes. Both old ports timed out afterward; full-site check mode
had zero drift, all 42 Compose services were running and current-artifact
backup admission passed. One immediate post-reset health observation failed;
required containers were healthy on direct inspection, and repeat observation
passed. The cause was not established. Actual CI, isolated remote GOST denials,
and UDP/HTTP3 remain unverified despite retirement.

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
   create-only operation, expected identity name and known fields,
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

## Ordered deployment after AWS approval (historical checklist)

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
   public Traefik untouched and Serve active. Stage and verify DNS-01 first;
   separately approve production-CA promotion and verify Omada API authentication
   and CLIProxyAPI management/API-key paths with strict client TLS. An Omada
   backend TLS exception must remain confined to `127.0.0.1:8043`.
3. Change Tailscale grants to permit owner/admin and CI on Docker-host TCP
   443; test both routes from owner and CI, and an unauthorized tailnet source.
   From outside the LAN, force each `*.ts.diloreto.com` hostname to the public
   IP and verify no application route; test from the LAN and against both WAN
   forwards. Actual ephemeral CI runner checks remain deferred until that
   runner exists; never infer them from policy tests.
4. The Omada provider URL and protected export helper have moved, with an
   authenticated export and no-op plan. The separately approved host GOST
   matcher and work-Mac first-hop/base-URL changes have been rolled out; the
   operator reports real authenticated work-Mac access and Tailscale control
   working. PAC remains off. An isolated authenticated client **without local
   bypasses** must still verify remote LLM/Omada CONNECT and refusal of
   MagicDNS/other public hosts, the private-zone apex, IP literals and alternate
   ports. Work-Mac positivity does not establish these server negatives or make
   old LLM endpoints unused for CI. The dotfiles are a separate authority;
   retain Tailscale coordination; Serve was retained until the separate
   retirement stage.
5. The operator requested Serve retirement while waiving actual ephemeral CI,
   isolated authenticated GOST denial and UDP/HTTP3 checks; preserve that
   residual risk explicitly. Before changing the host, admit a complete
   backup chain for its current Compose artifact and verify exact ownership of
   the node-level two-route Serve configuration. Reset **only that observed
   owned configuration**, then test both new routes and closure of the old
   ports. Separately review and approve an exact saved Tailscale plan removing
   only the `8443`/`8444` grants, keeping TCP 443 and SSH. Do not remove the
   Omada or CLIProxyAPI loopback backends: private Traefik still uses them.
   Reobserve Compose, backups and provider state; keep independent rollback
   access and preserved before-images until the result is qualified.
