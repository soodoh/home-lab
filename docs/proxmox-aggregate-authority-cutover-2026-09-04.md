# Proxmox aggregate authority cutover — 2026-09-04

The aggregate Proxmox lifecycle mutation owner transferred from Nix to Ansible after every modeled domain handoff was already `transferred` and single-writer, and after the operator explicitly confirmed attended physical-console recovery.

Cutover admission was bound to:

- clean pushed revision `776e8ca98bf70a82d791e9d76926132dfb14c9df`;
- saved zero-action Nix host plan `138989b15f53698190ba9e278be0a79d3ce487606296da7c65a64b4c5cd18a41`;
- saved controller manifest `6d7b1b11db2dac7525200250afeb25ffdf74402e43fa8d6950ed7c30095d7ec6`;
- zero-action OpenTofu plans for `aws-foundation`, `proxmox`, `omada`, `tailscale`, and `authentik`;
- independent live Ansible parity across 17 domains, recorded in [`../infrastructure/evidence/proxmox-ansible-parity-2026-09-04.json`](../infrastructure/evidence/proxmox-ansible-parity-2026-09-04.json);
- fixed plan/deploy transports, lock compatibility, PVE firewall CAS/watchdogs, storage/NFS checks, and physical-console recovery.

This transfer does not authorize package changes, reboot, firewall changes, storage changes, VM 100 changes, API-token removal, or deletion of rollback assets. Transitional Nix observer/build material remains read-only until the separate stale-authority retirement gate. OpenTofu remains authoritative for PVE API resources and retains separate plan/apply principals.

Post-cutover revision `40af5e2adc0513ef227a2c477f04d4e5fb8c363b` passed the full repository validation, a second 17-domain live Ansible audit (`parity: true`, observation `bd0b3b632651ffa4b2c884d85e4f2fed5305135244ed371c2a8eedec1bb4812d`), and a fresh controller plan with five zero-change OpenTofu roots, zero Nix compatibility actions, and manifest `9bec79037705105ecf2c0ae4a3bbb4c8dd41ed9272cdc575bc09cf9849f6dbd7`.
