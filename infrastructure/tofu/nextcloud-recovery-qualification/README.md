# Nextcloud recovery qualification foundation

This root owns only the stopped VM9000 foundation. It cannot start the guest.
It is not a general Proxmox deployment root.

## Ownership

- State path: `.local/nextcloud-recovery-qualification.tfstate`
- Owned VMID: `9000`
- Production VMID `100` and retired qualification VMID `9900` are excluded.
- The state must start absent and must never be copied from, imported into or shared
  with another root.
- `.local`, `.terraform`, saved plans and provider credentials remain untracked.

The provider uses the API credential supplied outside this root and the existing
`proxmox` SSH operator through the controller's SSH agent. SSH is required for the
cloud-init stream upload and image import. No password or private key belongs in
OpenTofu variables or state.

## Inputs

`foundation.tfvars.example` is deliberately invalid and is not auto-loaded. A
separately reviewed input must bind one ephemeral controller IPv4, one dedicated
public key and its exact digest, and the current isolation-attestation digest.

`enable_foundation = false` creates nothing. With the foundation enabled,
`retrieval_nic_enabled = true` declares exactly one firewall-enabled retrieval NIC.
After the guest is independently proven stopped, setting it to `false` produces an
explicit empty network-device list. The pinned provider uses that value to delete
`net0`; omitting the block would only stop managing the NIC.

## Gates

Provider initialization, each plan, foundation creation, startup, NIC removal,
offline startup and cleanup are separately authorized operations. Before the first
plan, require an absent dedicated state path, an unused VMID 9000, admitted host
memory reserve, exact ephemeral inputs, and review of the saved plan. Never run a
startup or recovery service from this root.
