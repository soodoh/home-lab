# Trusted local controller

Paul's MacBook is the interactive infrastructure controller. GitHub is only a Git remote; branch names, pull requests, `main`, and remote refs are not authorization boundaries. Any clean committed revision may be planned and applied.

## Safety boundary

- The complete working tree, including untracked files, must be clean.
- The saved manifest records the exact commit, operation, Compose artifact hash, and every plan hash.
- Plan and apply use separate mode-`0600` JSON credential files.
- Apply verifies the exact saved plans without replanning and atomically consumes the approval before its first apply attempt.
- Native OpenTofu S3 lockfiles and host-side mutation locks serialize changes.
- Each apply requires a local manifest-bound approval; CT unprotection and deletion remain separate approvals.
- Plans remain under the ignored `.reconcile/` directory on the FileVault-protected controller.

## Protected controller configuration

Create `~/.config/home-lab/controller` with mode `0700`. The controller reads:

- `plan-credentials.json`
- `apply-credentials.json`
- `roles-anywhere-plan.pem` and its private key
- `roles-anywhere-apply.pem` and its private key
- the local Roles Anywhere CA material
- `bin/aws_signing_helper`

Credential JSON is an object of environment variable names and string values. It contains protected provider values such as the backend identity, provider CA PEMs, provider endpoints, and separate provider credentials. Never commit, print, pass, or copy these values into command arguments or logs.

AWS uses separate, independently verified IAM Roles Anywhere certificates and profiles. The former hosted OIDC provider and DynamoDB lease are retired, and the foundation is converged under native S3 lockfiles.
Tailscale uses distinct local OAuth clients for plan and apply; the apply client intentionally lacks device-deletion authority. Omada uses distinct local viewer and administrator accounts. Their values live only in the corresponding protected JSON files.

Create the Tailscale plan client with `policy_file:read`, `federated_keys:read`, `devices:core:read`, and `devices:posture_attributes:read`. Create the apply client with `policy_file`, `federated_keys`, `devices:core:read`, and `devices:posture_attributes`; do not grant device deletion. In Omada, create a viewer for plans and a distinct administrator for applies. Run `scripts/configure-local-provider-credentials` locally to enter all four credentials through hidden terminal prompts; it writes only to the existing protected JSON files.

## Manual workflow

```sh
scripts/local-controller validate
scripts/local-controller plan steady
scripts/local-controller review steady
scripts/local-controller approve steady --confirmation apply-reviewed-steady
scripts/local-controller apply steady
```

Special operations use their own directories and confirmation phrases:

```sh
scripts/local-controller plan disk-growth
scripts/local-controller review disk-growth
scripts/local-controller approve disk-growth \
  --confirmation grow-reviewed-docker-root-disk
scripts/local-controller apply disk-growth
```

The Proxmox provider cannot update a VM containing an arbitrary host-path passthrough disk with a non-root API token. Disk-growth mode therefore uses the policy-inspected saved OpenTofu plan as the exact authorization record, applies every unchanged saved root plan, and realizes only the approved VM 100 `scsi0` resize through the guarded `tofu-apply` SSH identity. The host helper requires the protected `scsi1` identity, a running protected VM, the exact 400 GiB source geometry, the exact confirmation, and an exclusive lock before issuing `qm resize`; OpenTofu and guest checks must then prove 550 GiB convergence.

The one-time Tailscale hosted-identity cleanup is also separately bound:

```sh
scripts/local-controller plan tailscale-controller-retirement
scripts/local-controller review tailscale-controller-retirement
scripts/local-controller approve tailscale-controller-retirement \
  --confirmation retire-reviewed-tailscale-ci-identities
scripts/local-controller apply tailscale-controller-retirement
```

Planning a CT operation does not authorize it. Stop after review and obtain explicit approval before running the matching `approve` command. CT unprotection and deletion must never share one plan or approval.

The obsolete GitHub OpenTofu state was detached through an exact 26-address, single-transaction operation. The remote state is empty and all live repository protections remain unchanged.

## Repository hosting

The existing repository rules remain, except required Actions status checks are removed. Force-push prevention, deletion prevention, and pull-request rules remain active. No GitHub environment, OIDC, workflow, or deployment state is used by the controller.

## Containers and Coral

All Compose images retain an upstream tag and exact digest. Renovate updates the tag and matching digest, and local validation rejects any rendered service without both. Wolf is an ordinary Compose service and has no private child-image publication path.

Coral is built twice on the Docker host by Ansible from the exact tracked recipe inside a digest-pinned Arch build environment. The role requires byte-identical outputs and the contract checksum before local installation, then verifies DKMS and runtime state and removes the temporary build.
