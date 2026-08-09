# Tailscale local-controller operation

Tailscale remains a separate OpenTofu failure domain with strict saved-plan controls. The trusted MacBook controller uses two independent OAuth clients stored only in its mode-`0600` credential JSON files:

- **plan**: `policy_file:read`, `devices:core:read`, `devices:posture_attributes:read`, and `federated_keys:read`;
- **apply**: the corresponding policy, posture-attribute, and federated-key write scopes, with device-core read access but no device deletion authority.

Neither client receives a GitHub subject, enrollment tag, or stale-device deletion capability. Direct access comes from the operator's existing Tailscale user/device identity.

## CI identity retirement

The one-time `tailscale-controller-retirement` operation is policy-inspected and separately approved. Its exact plan must contain:

1. one complete live-policy transition removing `tag:ci`, `tag:ci-plan`, and `tag:ci-apply` ownership, grants, SSH rules, and tests while preserving owner/admin direct access; and
2. deletion of exactly the four obsolete federated identities.

```sh
scripts/local-controller plan tailscale-controller-retirement
scripts/local-controller review tailscale-controller-retirement
scripts/local-controller approve tailscale-controller-retirement \
  --confirmation retire-reviewed-tailscale-ci-identities
scripts/local-controller apply tailscale-controller-retirement
```

Apply rechecks the live policy SHA-256 and ETag against the exact saved-plan before identity, performs an `If-Match` update, applies the exact state plan, proves live policy equals state, and requires a fresh OpenTofu no-op plus host audit. It does not delete any Tailscale device.

Gateway policy stages remain `active`, `detached`, and `retired`. The current `detached` stage preserves the infra-router recovery path but contains no hosted-controller identity. Final gateway retirement still requires separate device-absence approval after CT retirement.
