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
or to deployment artifacts. Provider credentials are supplied to the current process
by the relevant setup helper or credential store.

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

The public `ts-control.diloreto.com` endpoint reaches GOST only through the
Authentik embedded proxy. Authentik intercepts HTTP Basic credentials on the
WebSocket handshake and authorizes only the dedicated service account's exact
application binding. The app password is created manually, has no expiry, and
is stored only as age ciphertext in the work-Mac dotfiles profile; it is not a
Compose or OpenTofu input. Revoke it in Authentik and terminate the active
WebSocket when immediate invalidation is required.

GOST has no published host port and no reusable server-side credential. Its
whitelist permits only `tailscale.com` and subdomains on TCP ports 80 and 443.
Keep both the Authentik identity gate and the GOST destination boundary: either
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
