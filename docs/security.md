# Security boundary

## Protected output

Never print or commit:

- decrypted SOPS values or resolved Compose configuration;
- OpenTofu state, plan JSON or saved plans;
- provider tokens, recovery credentials or bundle plaintext;
- private application paths, filenames or user content from recovery output.

Use `no_log: true`, private temporary directories and bounded summaries. Remove
private temporary output when the current run ends.

## Secrets

`secrets/production.sops.yaml` is the structured encrypted application source.
Compose deployment decrypts it through `community.sops` on the controller; provide
the age identity through `SOPS_AGE_KEY_FILE`. The identity is never copied into Git
or to deployment artifacts. For a local controller, separate plan/apply provider
identities may be exported from a mode-0600 gitignored `.env` or a protected
credential store. The local file is persistent plaintext: protect it independently,
never commit or log it, and rotate credentials if it is exposed. The non-AWS helper
reads exported provider variables without prompting and creates disposable
per-run credential files. Do not keep those files across sessions. Proxmox disk
and USB identities are reviewed in Git; fresh read-only host observation must
match them and the host's sealed hardware inputs before planning Proxmox changes.

The repository may contain public age recipients, public certificates and CA
certificates when they are trust inputs rather than proof of a completed action. The
Omada provider and export helper use the Docker host's tailnet-only Tailscale Serve
endpoint on TCP 8443. Controllers strictly verify its publicly trusted certificate
with the system trust store and hold no Omada CA or server private key. Omada forces
API login from HTTP to its private-CA HTTPS listener, so the one bounded exception is
Serve's encrypted but unauthenticated `https+insecure://127.0.0.1:8043` backend hop.
That hop cannot leave the Docker host; accepting it treats local host compromise as
already inside the provider trust boundary. Do not broaden the exception to a LAN or
tailnet address, restore a hostname alias, expose a loopback listener, or disable
client-side TLS verification.

## CLIProxyAPI tailnet boundary

Tailscale Serve terminates HTTPS for CLIProxyAPI on the Docker host's tailnet
identity at port 8444; Docker publishes its backend only on 127.0.0.1:8317.
The API key and separate full-privilege management key are age-encrypted in
`secrets/cli-proxy-api.sops.yaml` and rendered only to a root-owned protected
runtime config. The management UI has no account-only role: its key can read,
replace or delete OAuth auth files and change settings. Treat UI settings edits
as drift from Git and SOPS. OAuth refresh/session files in the bind mount are
sensitive and intentionally enter the encrypted local/NFS/Proton backup chain.
Never expose the OAuth callback port on any host network interface. The public
`gost.diloreto.com` WebSocket proxy also permits a CONNECT to this exact
Serve hostname and port, but does not publish an unauthenticated HTTP route to
CLIProxyAPI. Authentik gates the proxy handshake with the existing service-account
app password; the API and management keys remain separate service credentials.
Anyone who holds the proxy credential can reach all paths on the Serve endpoint,
including management, subject to the distinct management key. The proxy cannot
restrict paths inside the HTTPS tunnel. Treat loss of that credential as loss of
this network boundary and revoke it as described below.

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
whitelist permits only `tailscale.com` and subdomains on TCP ports 80 and 443,
plus `docker-host.tailea1a78.ts.net:8444` for CLIProxyAPI. Do not turn this
into a general-purpose forward proxy or admit other tailnet destinations. Keep
both the Authentik identity gate and the GOST destination boundary: either
control alone is insufficient for an Internet-facing relay.

## OpenTofu state and plans

Active roots use remote S3 backends. Run `tofu init` and a fresh plan for every
session. Keep saved plans in a private temporary directory and never inspect them by
printing raw JSON. Use [`scripts/inspect-tofu-plan`](../scripts/inspect-tofu-plan)
for bounded policy inspection.

A local-state-only root is not deployable. Migrate or retire its ownership before
removing local state.

## Recovery material

Restic passwords, Proton credentials, age identities and encrypted recovery bundles
belong in independent protected storage. Bundle metadata contains only identities
freshly observed from the selected live repository chain. It does not contain or
hash historical Git receipts.
