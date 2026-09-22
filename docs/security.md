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
certificates when they are trust inputs rather than proof of a completed action.

## SSH and privilege

[`ansible/inventory/hosts.yml`](../ansible/inventory/hosts.yml) fixes the
Omada-reserved LAN addresses, `ansible-deploy` users, host-key aliases and
noninteractive native OpenSSH policy. The selected public identity is committed as a
trust input; its private key remains in the Bitwarden SSH agent and is selected
through `${SSH_AUTH_SOCK}`. Host changes use Ansible become. Tailscale is personal
access only and is not a deployment transport. See
[deployment access](deployment-access.md) for the current path and future CI
boundary.

Observe independent console or personal Tailscale access before work that can change
networking, firewall, storage or boot behavior.

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
