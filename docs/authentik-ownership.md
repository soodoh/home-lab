# Authentik ownership

The `infrastructure/tofu/authentik` root defines application/provider configuration,
access bindings, custom authentication and invitation-enrollment flows, their
supporting stages, application-access groups, password-change policy, default brand
selectors and provider-exposed system settings. Remote S3 state defines ownership;
import IDs and desired values are not proof that adoption has completed. Follow
[operations](operations.md) for fresh observation, complete saved-plan review,
separate apply approval and a subsequent no-op plan.

Run `scripts/test-authentik-tofu` for native offline behavioral checks. OpenTofu's
mock-provider framework cannot execute imports, so the small test adapter omits
only `imports.tf` from a disposable copy; it tests unchanged resource declarations
with synthetic fixtures and no inherited provider credentials. These tests do not
replace the live, remote-backed import plan.

## Directory and onboarding

Application-access membership is Git-owned. `membershipSets` defines the shared
`family`, `caro`, `personal` and `operators` username lists once; each `groups.*.membership_set`
selects one list. Native provider data sources resolve independently owned users;
the root never creates or changes those accounts, their passwords or their
personal authenticators. These are flat groups with no parents or superuser status.

| Access group | Membership set | Applications |
| --- | --- | --- |
| Jellyfin (existing media entitlement) | family | Jellyfin, Seerr |
| Karaoke Users | family | Karaoke Eternal |
| Caro Library Users | caro | Caro Tachidesk |
| CWA Users | personal | Calibre-Web-Automated, Grimmory |
| Camera Viewers | personal | Frigate |
| Vaultwarden Users | personal | Vaultwarden |
| App Operators | operators (Paul only) | Calibre, CWA, Caro Tachidesk, DDNS Updater, Frigate, Home Assistant, Karaoke Eternal, Mindwtr, Openfit, Prowlarr, qBittorrent, Radarr, Radarr 4K, Readarr, SABnzbd, Sonarr, Tachidesk, Vaultwarden, Z-Wave |

Grimmory has a new create-only provider/application during the [CWA transition](grimmory.md),
not an invented import ID. It shares the existing personal entitlement without
auto-provisioning directory users or mapping application access to admin roles.
Its separate client secret uses the same Authentik SOPS authority; its signed OIDC
client uses a dedicated create-only RSA signing certificate in the existing
SOPS/OpenTofu signing authority, not a competing discovery-owned key writer. Keep CWA/Calibre ownership until validation; their
retirement requires explicit reviewed destroy actions.

`App Operators` grants application access, not in-application administrator roles.
`authentik Admins` and its independently administered membership grant Authentik
administration only; application bindings do not reference that group. Shared
applications combine their specific access group and `App Operators` using `any`
(OR). Jellyfin and Seerr retain the media group rather than an operator binding;
Paul accesses them through his media membership. Direct-user exceptions are not
retained alongside the entitlement groups: they would bypass membership removal.
GOST keeps its separate exact service-account binding.

Nextcloud is not an Authentik application in this root. Its existing Paul/Sarabeth
native accounts and data remain independently owned; no unused Nextcloud access
group claims to enforce login. OIDC integration is a separate reviewed change that
must preserve user IDs, data ownership and independent recovery.
Every username must resolve to a distinct user. The group's existing external role
association is preserved, but that role and administrator/break-glass memberships
remain independently administered. Group updates send a complete membership list:
serialize applies against manual membership edits and review removals as access
changes, even when the resource itself is not being deleted. After invitation
enrollment, add the admitted user's username to desired membership before the next
apply; otherwise Git-authoritative convergence will propose removing that new
member. Adding a user to `family` grants both media and karaoke entitlements;
review the complete access matrix when changing a shared membership set. Enrollment's runtime addition is not a persistent membership authority.

The invitation-enrollment flow requires an invitation before collecting account
fields, creates active external users in Jellyfin, then logs them in. Individual
invitations are transient and are not OpenTofu-owned. The identification stage has
no public enrollment link. Enrollment prompt stages deliberately retain their
existing empty password-validation-policy lists; adoption does not attach the
password-change policy to onboarding or strengthen authentication implicitly.

The shared identification stage references the owned passwordless validation stage.
WebAuthn setup requires resident keys and keeps its configured attempt limit.
Default MFA validation retains `not_configured_action = "skip"`; owning that stage
does not make MFA enrollment mandatory. Unchanged shared password/login stages and
stock flows remain data-source references rather than additional writers. The
identification stage also retains its owned passwordless-flow selector.

Provider 2026.8.0 writes login-stage `network_binding` and `geoip_binding` but
omits both from its reader. Permanent lifecycle exclusions avoid false import
updates; the plan-input preflight independently compares both live values to Git
and refuses drift. Keep the preflight mandatory; remove these exclusions only
with a provider version that round-trips the fields and a fresh complete plan.

## System and notification boundaries

The default brand's supported selectors and all provider-exposed system settings
are explicit desired state. In particular, the effective `core_default_app_access`
flag is preserved rather than inherited from the provider's different default.
Application access bindings remain separately owned and must still be evaluated.

The pinned provider does not expose the native system settings `base_url` and
`impersonation_require_reason`, or the brand's `flow_request` and `flow_user_switch`
fields. These remain Authentik-owned; do not claim complete ownership of their
containing native documents. SMTP/runtime configuration and outpost container
execution remain Compose/SOPS-owned. Stock mappings, built-in source, internal JWT
certificate and routine schedules remain native-owned. Notification rules are
outside this root; a change to their recipient policy requires separate approval.

## Signing material

`jellyfin-oidc.pem` is public certificate material for Jellyfin OIDC's existing
self-signed signing key. Its private key is authoritative in the separately
encrypted `signing-keys.sops.json`, decrypted only into the current private
controller session through `TF_VAR_authentik_signing_keys_path`. The provider's
private-key read must succeed before planning; its reader silently omits key data
on an unsuccessful private-key export, which would otherwise cause a false update.
Keep remote state, saved plans and all decrypted inputs protected. Configuration
adds the pinned reader's extra newline to native PEM exports for comparison;
this representation adjustment does not change cryptographic material.

`grimmory-oidc.pem` is the dedicated Grimmory signer's public certificate; its
private key is another entry in the same encrypted `signing-keys.sops.json`
authority. Its null observed ID excludes it from imports, and the provider uses
a symbolic managed-certificate reference. Existing signer declarations and key
material remain unchanged. After creation, exact-name discovery requires a
complete inventory and the new private-key read permission on every plan; a
create-only declaration is not a permanent permission exemption. Independently
review grants, certificate validity and served JWKS before activation. Supplied
certificates are not automatically renewed.

OAuth client secrets and the LDAP bind/TLS material retain their independent
`client-secrets.sops.json` authority. Signing-key adoption must preserve the existing
key and provider identifier; any rotation is a separate reviewed change requiring
consumer/JWKS and fresh-login verification. The certificate resource manages supplied
material, not issuance or automatic renewal.

Vaultwarden's discovery-managed signing certificate remains owned by Authentik's
certificate discovery and its protected Compose bind mounts. Do not import it into
OpenTofu without first resolving the competing writer and key custody. Removing a
managed certificate or declaration must produce a reviewed destroy plan, never an
orphaned state entry.

## Independent provider permissions

Provider accounts, tokens and the plan/apply roles' own grants remain outside their
OpenTofu root. An independent owner administers the required object read/change
permissions and singleton system-setting permissions. This is not permission for a
provider identity to broaden its own access. Plan credentials also retain the
explicit OAuth provider-change exception needed for secret reads; protect them as
mutating credentials. See [security](security.md#opentofu-state-and-plans).
