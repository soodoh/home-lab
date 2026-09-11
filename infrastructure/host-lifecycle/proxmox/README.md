# Proxmox host observation

This directory on `main` retains the older v6 observer source, deferred and unqualified—not a current maintenance default. The attended implementation is preserved in the complete accepted snapshot on local, unpublished branch `wip/deferred-attended-controller-3491395-01`, alongside independent improvements. See [ADR 0005](../../../docs/adr/0005-attended-operational-admission.md) and the [candidate source reference](../../../docs/local-controller.md); clean committed source grants no operation or installation authority. The legacy source description below does not describe installed capability.

- `observer-template.py` emits the canonical 17-domain observation without changing the host.
- `infrastructure/maintenance/host/package-candidate-observer` is the shared immutable APT candidate observer. The artifact builder embeds the exact PVE manifest into a separately hashed generated executable.
- `observation.schema.json` validates the bounded observation; `projection.schema.json` validates the derived execution model.
- `observer-artifact.schema.json` validates the controller-built artifact manifest.
- `scripts/controller/proxmox-host-projection.js` maps the authoritative `infrastructure/contract/home-lab.yml` and exact package manifest into the observer specification.
- `scripts/controller/build-proxmox-ansible-observer.js` renders an immutable observer artifact without invoking Nix.

Ansible already owns Proxmox. The tracked files under `nix/proxmox/` are retained compatibility/recovery inputs, not an enabled Nix mutation owner. Repository validation requires the observer template and observation schema mirrors to be byte-identical. New Ansible code must use this directory and must not consume installed Nix observation output as desired-state authority.

The parity observer still accepts only `version`, `self-check`, and `observe`, bounds command and final output sizes, emits canonical JSON, and exposes only redacted summaries for protected access and hardware. During Gate 2, those two summaries remain bound to the exact root-owned private preparer SHA-256 supplied at artifact build time. Moving that protected collector out of the Nix transaction boundary is a separate Gate 3 prerequisite; its temporary use must not be described as independent protected-domain parity.

The plan transport has a second exact literal, `observe-package`, which invokes only the generated package candidate observer. `ansible/playbooks/proxmox-packages-plan.yml` runs locally, first requires complete parity, verifies every controller artifact and manifest hash, then retrieves the bounded candidate through `ansible-plan@proxmox`. It never exposes a generic remote Ansible shell or deploy identity.

Generated artifacts are local evidence, not authorization and not consumable Ansible plans. The installed production transport does not gain `observe-package` until the new transport, generated observer, and exact sudo rule are installed together through a separately reviewed capability-upgrade transaction. Until that transaction and disposable denial proofs pass, Proxmox package planning remains blocked rather than falling back to the transitional human inventory.
