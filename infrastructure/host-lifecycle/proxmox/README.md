# Proxmox host observation

This directory is the neutral source boundary for the fixed, redacting Proxmox host observer used by Ansible planning.

- `observer-template.py` emits the canonical 17-domain observation without changing the host.
- `observation.schema.json` validates the bounded observation; `projection.schema.json` validates the derived execution model.
- `observer-artifact.schema.json` validates the controller-built artifact manifest.
- `scripts/controller/proxmox-host-projection.js` maps the authoritative `infrastructure/contract/home-lab.yml` and exact package manifest into the observer specification.
- `scripts/controller/build-proxmox-ansible-observer.js` renders an immutable observer artifact without invoking Nix.

The tracked files under `nix/proxmox/` are transitional compatibility mirrors while Nix remains the Proxmox mutation owner. Repository validation requires the observer template and observation schema mirrors to be byte-identical. New Ansible code must use this directory and must not consume installed Nix observation output as desired-state authority.

The observer still accepts only `version`, `self-check`, and `observe`, bounds command and final output sizes, emits canonical JSON, and exposes only redacted summaries for protected access and hardware. During Gate 2, those two summaries remain bound to the exact root-owned private preparer SHA-256 supplied at artifact build time. Moving that protected collector out of the Nix transaction boundary is a separate Gate 3 prerequisite; its temporary use must not be described as independent protected-domain parity.

Generated artifacts are local evidence, not authorization and not consumable Ansible plans. Installing different observer bytes is a production mutation requiring a separately reviewed saved-plan transaction through `ansible-deploy`.
