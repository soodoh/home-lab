# Security boundary

## Protected output

[Proxmox access ownership](proxmox-ownership.md#independent-access-ownership) is
separate from normal provider automation: owner-only state grants and ephemeral
owner provider credentials are required to manage the existing roles/token ACLs.
The desired normal automation grants exclude direct access-management authority:
`Sys.Modify` is scoped to `/nodes/proxmox`, not `/` or `/access`. Global cluster
options remain owner-only; cluster-firewall mutations also require independent
owner Proxmox apply credentials. The plan-token storage-read exception grants
`Datastore.Allocate` only at the three existing storage IDs: PVE requires it for
configuration reads and snippet visibility, but it also permits volume/snippet
deletion. Treat the plan credential as mutating, not read-only. Changes require
independent owner risk approval and sealed access expectation alignment;
declarations and observation do not themselves authorize a grant change.
Native snippet uploads retain Tailscale SSH without deployment keys; pre-pin the
provider's exact
node FQDN because it accepts unknown host keys.

Never print or commit:

- decrypted SOPS values or resolved Compose configuration;
- OpenTofu state, plan JSON or saved plans;
- provider tokens, recovery credentials or bundle plaintext;
- private application paths, filenames or user content from recovery output.

Use `no_log: true`, private temporary directories and bounded summaries. Remove
private temporary output when the current run ends.

## Secrets

`secrets/production.sops.yaml` is the structured encrypted application source.
[`Omada mail`](omada-mail.md) has a separate desired authority in
`secrets/omada-mail.sops.json`: dedicated SMTP token, server, sender and
required recipients. Native recipients are derived from independently owned
administrator account email/alert subscriptions; SMTP approval is not an account
mutation grant. The mail role requires those recipients before SMTP writes and
never PATCHes notifications or accounts. Capture and observation do not activate
SMTP. The approval-gated native Ansible mail interface decrypts on the controller
and protects requests with
`no_log` and verified HTTPS; SMTP tokens are masked by the API and cannot be
compared during a normal observation. Omada has no documented SMTP password-file
reader; do not inject these values into Compose or claim that a secret mount
configures its native controller settings.
Authentik OAuth client secrets are instead authoritative in
`infrastructure/tofu/authentik/client-secrets.sops.json`. Site convergence reads
that source on the controller to render Home Assistant's protected `!secret`
entry and Vaultwarden's protected client-secret file. Grimmory uses the same
encrypted authority through its native admin settings API, with controller-side
Ansible `no_log` tasks and verified HTTPS; it has no native OIDC secret-file reader.
Its database/bootstrap credentials and shared `HARDCOVER_API_KEY` remain in
production SOPS. Ansible merges only the Hardcover metadata key into native
provider settings, preserving enablement and other provider credentials; per-user
reading-progress sync tokens remain application-owned. The database password uses
Spring Boot's native `configtree:` reader. See
[native authentication convergence](operations.md#grimmory-native-authentication-and-library-ownership)
for local-administrator recovery and approval-gated settings changes.
Only the public Vaultwarden client ID
is added to Compose's interpolation environment, from Authentik's reviewed `desired.json`.
Jellyfin OIDC's existing signing key has separate authority in
`infrastructure/tofu/authentik/signing-keys.sops.json`; Grimmory's dedicated RSA
key uses that same authority without rotating existing material. Public
certificates are not secret. Its private-key export must be readable by the plan identity, and
both decrypted secret inputs, state and plans remain protected. Discovery-owned
signing certificates must not acquire a competing writer; see
[Authentik ownership](authentik-ownership.md).
Shelfmark consumes the existing Prowlarr key, Hardcover token
(`HARDCOVER_API_KEY` in production SOPS) and download-client credentials
through Ansible-managed fields in its native settings JSON, protected as
UID/GID 1000 mode 0600 inside its backed-up private config directory. The role
preserves unrelated fields, stops only Shelfmark for changed files and tests
the native reader against an ephemeral private copy: importing that reader
otherwise writes environment defaults back into live settings. Hardcover's
read-only account test also updates connection metadata only in that private
copy; source enablement and unrelated settings remain application-owned.
No new credential authority, secret environment variables or OpenTofu state fields are added.

Compose deployment decrypts SOPS inputs through `community.sops` on the controller; provide
the age identity through `SOPS_AGE_KEY_FILE`. The identity is never copied into Git
or to deployment artifacts. For a local controller, separate plan/apply provider
identities may be exported from a mode-0600 gitignored `.env` or a protected
credential store. The local file is persistent plaintext: protect it independently,
never commit or log it, and rotate credentials if it is exposed. The dedicated
tailnet Traefik ACME access key is held as ciphertext in
`secrets/production.sops.yaml` and rendered into a root-only AWS shared
credentials file. Only private Traefik mounts it; public ingress must never
inherit it. [`services/credentials.json`](../services/credentials.json) declares
raw/structured credential files, actual host reader permissions and the explicit
remaining interpolation inputs. Openfit is excluded: its two secrets remain in
the protected `production.env` and its container environment. Other migrated
inputs use existing application/image file interfaces, not custom entrypoints.
LinuxServer and PostgreSQL still export file contents inside the process tree;
file delivery is not universal memory or log redaction. Host files are plaintext,
individually mounted read-only and included in encrypted backup/recovery scope.
See the [delivery audit](compose-secrets.md) for native readers and caveats. Staging and production certificates have separate
root-only ACME stores excluded from Restic. Production TLS and tailnet grants do not prove CI/application authentication,
remote GOST destination denials or UDP/HTTP3 negative paths; verify these
against current live state before relying on them. The non-AWS helper
reads exported provider variables without prompting and creates disposable
per-run credential files. Do not keep those files across sessions. Proxmox disk
and USB identities are reviewed in Git; fresh read-only host observation must
match them and the host's sealed hardware inputs before planning Proxmox changes.

The repository may contain public age recipients, public certificates and CA
certificates when they are trust inputs rather than proof of a completed action.
The Omada provider and export helper use `omada.ts.diloreto.com` on tailnet
TCP 443 and strictly verify private Traefik's publicly trusted certificate.
For the separate backend hop, private Traefik trusts only the observed Omada
self-signed public certificate in `services/data/traefik-tailnet/omada.pem` and
verifies its `Omada` DNS name over a dedicated two-container Docker bridge.
No Omada private key enters Git or the controller. Before deployment, compare
the live backend certificate fingerprint and SAN against the committed trust
input; certificate rotation must update the reviewed trust input before the
old one expires (October 2028). A mismatch must fail closed; do not disable
backend or client-side TLS verification, substitute a LAN/tailnet address, or
restore a hostname alias.

## Grimmory account and device access

Authentik entitlement admits login, not administrator privileges or library access.
Grimmory auto-provisioning creates non-admin accounts with empty default permissions
and library assignments; grant access separately. Local-account linking and group
privilege synchronization remain disabled. Offboarding must review existing
Grimmory accounts, permissions and sessions independently of directory entitlement.
Do not recycle an OIDC username while its Grimmory account exists: the pinned login
implementation also falls back to usernames, not only issuer/subject.

Kobo tokens are separate credentials from OIDC; protect tokens and token-bearing
URLs. Each owner's dedicated `Kobo` shelf controls selection; ordinary/history
shelves must not expand it or enable automatic addition. Pinned v3.5.0's direct
Kobo download route does not enforce assigned-library access. This native behavior
is accepted for this deployment; library grants do not provide complete
device-route isolation.

## Mindwtr access

Authentik gates the web UI at `todo.diloreto.com`, not Cloud sync clients.
`/v1/*` reaches Mindwtr Cloud without web forward-auth; regular API and sync
requests require the fixed Cloud token. A calendar feed created through the
authenticated API uses its own revocable URL token at `/v1/calendar/<token>.ics`.
Treat that URL as a secret; do not require the fixed token on the feed route.
Unknown and revoked feed URLs must not return task data.

## CLIProxyAPI tailnet boundary

Private Traefik terminates HTTPS for CLIProxyAPI at `llm.ts.diloreto.com`
on tailnet TCP 443; the old Tailscale Serve port 8444 is closed. Traefik
reaches `cli-proxy-api:8317` on the Docker proxy bridge; the existing host
binding remains limited to 127.0.0.1:8317.
The API key and separate full-privilege management key are age-encrypted in
`secrets/cli-proxy-api.sops.yaml` and rendered only to a root-owned protected
runtime config. The management UI has no account-only role: its key can read,
replace or delete OAuth auth files and change settings. Treat UI settings edits
as drift from Git and SOPS. OAuth refresh/session files in the bind mount are
sensitive and intentionally enter the encrypted local/NFS/Proton backup chain.
Never expose the OAuth callback port on any host network interface. The public
`gost.diloreto.com` WebSocket proxy is now configured for `tailscale.com` and
its subdomains on ports 80/443 and `*.ts.diloreto.com:443` only; the old
any-port MagicDNS matcher is removed from the running host config. Authentik
gates the proxy handshake with the existing service-account app password; the
API and management keys remain separate service credentials. The proxy
credential permits attempts to reach all listed private routes, including
Omada, Proxmox and Z-Wave. Omada and Proxmox use their native logins; Z-Wave's
private UI stays behind its existing Authentik application and group binding.
The relay handshake does not authenticate a backend. Tailscale evaluates
relay egress as the Docker-host node, not the work Mac. GOST cannot filter paths inside HTTPS tunnels. The
operator reports work-Mac first-hop LLM/Omada application access and Tailscale
coordination working, but its system PAC is **off** and remote authenticated
whitelist refusal remains untested. Treat loss of the proxy credential as loss
of this network boundary and revoke it as described below.

## Automatic Compose deployment credentials

The approved routine deployment lane stores the operator-authorized age identity
only in the main-restricted `infrastructure-deploy` environment's `SOPS_AGE_KEY`
secret. This grants trusted main deployment jobs decryption authority for every
SOPS file covered by that identity. PR validation receives neither that secret
nor an OIDC grant. The deploy job uses private mode-0600 controller files and
removes them on every exit; never upload decrypted files or source/state archives.
Tailscale access uses the exact federated environment subject and ephemeral nodes,
not a stored auth key, OAuth secret or native SSH key. See
[deployment access](deployment-access.md#github-hosted-runners).

## SSH and privilege

[`ansible/inventory/hosts.yml`](../ansible/inventory/hosts.yml) fixes the Tailscale
MagicDNS names, `ansible-deploy` users, host-key aliases and credential-free OpenSSH
client policy. Tailscale authenticates the source identity and Tailscale SSH maps it
to the local account; native authorized keys remain absent. Host changes use Ansible
become. See [deployment access](deployment-access.md) for the local path and the
narrow GitHub workload-identity boundary.

Observe independent console access before work that can change Tailscale, networking,
firewall, storage or boot behavior.

## Tailscale coordination proxy

The public `gost.diloreto.com` endpoint reaches GOST only through the
Authentik embedded proxy. Authentik intercepts HTTP Basic credentials on the
WebSocket handshake and authorizes only the `gost-proxy-user` service account's
exact application binding. Its `gost-proxy` app password is created manually,
has no expiry, and is stored only as age ciphertext in the work-Mac dotfiles
profile; it is not a Compose or OpenTofu input. Revoke both the old
`tailscale-control-proxy` app password and the new app password when applicable;
terminate active WebSockets when immediate invalidation is required.

GOST has no published host port and no reusable server-side credential. Its
reviewed whitelist permits `tailscale.com` and subdomains on TCP 80/443, plus
`*.ts.diloreto.com:443`; it does not declare any-port MagicDNS access or arbitrary
Internet destinations. Docker's default DNS cannot resolve MagicDNS. Only GOST
uses `100.100.100.100` for peer names and the host-observed `1.1.1.1` fallback
for public Tailscale control names; site convergence checks the resolver pair
and host's current DNS. Do not disable client TLS verification or remove
Authentik's identity gate. Check the **live** remote whitelist with an isolated
authenticated client without a local bypass; source alone does not prove what
that server currently denies. A stolen relay credential can attempt all listed
private application routes through the Docker host's identity, subject to
application authentication and Tailscale policy. Proxmox needs its native
login; Z-Wave remains Authentik-protected. The bridged private Traefik reaches
Authentik's embedded proxy at `authentik-server:9000` without a host port;
Z-Wave's UI port 8091 has no published host binding. Docker publishes private
Traefik's TCP 443 only on the reviewed Docker-host Tailscale IPv4.

## Wolf container authority

Wolf intentionally controls the production rootful Docker daemon. Its compromise
can compromise the entire application host; image pins, pairing and ingress rules
reduce exposure, not that authority. GPU sharing remains unchanged. Steam's
application-specific capabilities and seccomp/AppArmor exceptions are not removed
without a qualified gaming test.

[`security.json`](../services/data/wolf/security.json) owns spawned image
references and the six streaming/control ports. Native Ansible owns only the
`inet home_lab_wolf` nftables table, its systemd unit and persisted TOML `image`
assignments. Never flush Docker/Tailscale rules or enable the packaged general
`nftables.service` with its default flush-ruleset configuration. The scoped unit
is required before Docker starts on subsequent boots; stopping it leaves its
rules in place. Its earlier INPUT hook allows loopback, `192.168.0.0/24` on
`ens18`, and Tailscale ingress. Tailscale separately admits those ports only for
owner devices, not CI or administrator-only identities. IPv6 LAN streaming is
not admitted. Shared mDNS port 5353 is unchanged and is not granted over tailnet;
this policy does not hide LAN discovery or authenticate a backend.

Other app definitions, paired clients, certificates and profile data remain
Wolf-owned and backed up. The native API supports append/remove, not image-only
updates. Convergence requires no active sessions or lobbies and admits the
observed private configuration (UID/GID 1000, mode 0600) before firewall writes.
It stops only Wolf, retains a protected complete configuration before-image,
changes only the declared image fields, preserves application ownership and
checks the complete changed settings again after healthy startup. Unknown, duplicated
or retargeted images refuse admission. It does not launch Steam or an emulator
or prove first-use application compatibility. Image digest updates are reviewed
changes, including Renovate candidates; changing tags also requires reviewing
the declared source identity.

## OpenTofu state and plans

Active roots use remote S3 backends. Run `tofu init` and a fresh plan for every
session. Keep saved plans in a private temporary directory and never inspect them by
printing raw JSON. Use [`scripts/inspect-tofu-plan`](../scripts/inspect-tofu-plan)
for bounded policy inspection.

A local-state-only root is not deployable. Migrate or retire its ownership before
removing local state.

Authentik omits OAuth client secrets from its provider API response unless the
caller has provider change permission. The Authentik OpenTofu plan identity
therefore needs that permission on every existing managed OAuth provider to plan
secret rotations without false updates on every refresh. Grant it on those
objects rather than globally if the live RBAC model permits. This is an
explicit exception to a read-only plan identity:
protect its credential as a mutating credential, and do not plan until the
independently owned grant has been reviewed and installed. The plan-input
preflight refuses an identity that cannot read all managed OAuth secrets without
printing them. The apply identity remains separate. Both identities' provider
reads and any saved plans/state can contain client secrets; keep them private.

The Arr applications expose only one full-privilege API key per instance. The
owner explicitly accepts a narrow exception to separate plan/apply provider
identities for the Servarr root: both operations use that same key, solely from
a fresh mode-0700 controller session prepared from protected SOPS, with a
reviewed saved plan and separately approved apply. This does **not** make a
plan read-only; protect the controller accordingly. The qBittorrent and SABnzbd
connection secrets become sensitive OpenTofu resource attributes, so protect
remote state and private plans in addition to the encrypted SOPS sources.
Private Arr provider routes should forward only native API paths over tailnet
HTTPS. The native API key remains essential authorization: the GOST relay can
attempt the permitted `*.ts.diloreto.com:443` private routes after its own
handshake, so a private hostname or relay authentication alone is insufficient.

## Recovery material

Restic passwords, Proton credentials, age identities and encrypted recovery bundles
belong in independent protected storage. Bundle metadata contains only identities
freshly observed from the selected live repository chain. It does not contain or
hash historical Git receipts.
