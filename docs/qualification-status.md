# Qualification status

## Statically implemented

- contract and JSON-schema validation
- provider lock validation and policy-inspected saved plans
- isolated OpenTofu roots and serial apply orchestration
- Proxmox/Arch bootstrap and steady Ansible gates
- exact backup-ID, version, checksum, archive, and fresh-target recovery controls
- current/previous Compose locks with uniform readable-tag plus digest image pins
- trusted local-controller plan/apply credential separation and protected confirmation gates
- static recovery fixtures and playbook syntax rehearsal
- isolated saved-plan Proxmox LXC lifecycle qualification, exact policy modes, protected-delete classification, identity proofs, and empty-state tombstone controls

## Live qualified

- Omada strict-TLS export and import-only adoption of the existing LAN and 17 DHCP reservations
- Omada disposable reservation create/read/delete behavior with separated plan/apply identities
- three consecutive protected no-op Omada plans after cleanup
- schema-valid six-operation disposable Proxmox LXC lifecycle evidence and the enabled provider gate
- separately staged CT 101 unprotection, full no-op proof, and deletion
- exact retired-CT Omada reservation deletion with every other reservation and root unchanged
- reproducible local Coral double-build, exact package checksum, installed marker, runtime, and Frigate health
- three-path local backup deployment with distinct filesystems and matching newest archive metadata

## Requires protected inputs

Backend coordinates, provider credentials, SSH fingerprints/keys, hardware identities, Omada export, backup object/version/checksum, GPG material, SOPS recipients, Coral artifact hashes, and recovery evidence are intentionally absent from Git.

## Requires live qualification

CT 101 retirement is complete: the container and adopted Omada reservation are absent, read-only Tailscale verification found no stale gateway device, and the exact `detached -> retired` gateway-policy plan converged with a full no-op proof. Scheduled daily/weekly backup evidence, disposable-VM Proxmox behavior, cold boot, and recovery-time objective remain operational observations rather than static claims.

Static validation must not be represented as production readiness. Update this document only with evidence from the protected qualification process; never paste secrets or protected identifiers.