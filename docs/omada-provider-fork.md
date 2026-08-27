# Temporary Omada provider fork

## Status

The Omada OpenTofu root temporarily runs the `soodoh/terraform-provider-omada`
fork because `wncservices/omada` 0.10.3 does not expose persistent client
aliases. The fork adds `omada_client_alias`, which adopts a known client by MAC
and manages only its friendly display name. DHCP reservations remain separate.

- Upstream provider source address retained in HCL: `registry.terraform.io/wncservices/omada`
- Fork repository: <https://github.com/soodoh/terraform-provider-omada>
- Fork branch: `feat/client-alias`
- Upstream pull request: <https://github.com/wncservices/terraform-provider-omada/pull/53>
- Pinned fork commit: `6d81edfd9f160c02eb53f5dc056dde857d8e5f8d`
- Temporary fork build version: `0.10.4-fork.3`

Keeping the upstream source address is deliberate. OpenTofu state provider
identities do not change during the temporary fork period, so returning to an
upstream release does not require `state replace-provider`.


## Encrypted client configuration

MAC-to-alias associations and the locally requested reservation are stored in
`infrastructure/tofu/omada/client-config.sops.json`. The document uses arrays of
objects rather than MAC-keyed maps so SOPS encrypts both the MAC addresses and
their associated names. The controller credential files must provide
`SOPS_AGE_KEY_FILE`; `scripts/prepare-omada-plan-input` validates that identity,
decrypts the document to `.local/omada/client-config.json` with mode `0600`, and
passes only that ignored local path to OpenTofu.

Removing an alias entry plans destruction of only its `omada_client_alias`
resource. Fork version `0.10.4-fork.3` clears the controller alias during destroy
by restoring the normalized MAC as Omada's unaliased display name; it does not
delete or block the network client.

## Installation and verification

`scripts/prepare-omada-provider-fork` fetches the exact public fork commit into
`.local/`, verifies the remote and commit, builds the provider, and writes a
root-only OpenTofu CLI configuration with a development override for
`wncservices/omada`. `scripts/reconcile-infrastructure` invokes it before Omada
validation, planning, and apply.

For local development, an existing exact, clean checkout can avoid another
clone:

```sh
OMADA_PROVIDER_FORK_SOURCE=/path/to/terraform-provider-omada \
  scripts/prepare-omada-provider-fork
```

The override disables normal package checksum verification, so the preparation
script compensates by accepting only the contracted Git commit. Never point
`OMADA_PROVIDER_FORK_SOURCE` at a dirty checkout or a different commit.

The fork itself must pass:

```sh
go test ./... -count=1
TF_ACC=1 go test ./... -v -count=1 -timeout 30m -run '^TestAcc'
golangci-lint run
go generate ./...
```

The home-lab Omada plan must then be reviewed normally. A second plan after apply
must be empty.

## Returning to the upstream provider

After the upstream client-alias pull request is merged **and included in a
published `wncservices/omada` release**:

1. Update `infrastructure/tofu/omada/versions.tf` to that released version.
2. Remove `scripts/prepare-omada-provider-fork` and every reference to it from
   both `scripts/local-controller` and `scripts/reconcile-infrastructure`,
   including preparation calls and the `shellcheck` argument.
3. Remove this document.
4. Run `tofu init -upgrade` for `infrastructure/tofu/omada` and commit the updated
   provider lock file.
5. Run a credentialed Omada plan and require zero replacement operations. The
   existing `omada_client_alias` state should refresh in place because the
   provider source address never changed.
6. Apply only the reviewed no-replacement plan, then require a second empty plan.

Do not revert merely when the pull request merges; wait until the resource is in
a signed, installable upstream release.
