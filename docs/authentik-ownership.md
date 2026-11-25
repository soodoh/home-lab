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
`family`, `caro`, `personal`, `uchiyomi` and `operators` username lists once; each `groups.*.membership_set`
selects one list. Native provider data sources resolve independently owned users;
the root never creates or changes those accounts, their passwords or their
personal authenticators. These are flat groups with no parents or superuser status.

| Access group | Membership set | Applications |
| --- | --- | --- |
| Jellyfin (existing media entitlement) | family | Jellyfin, Seerr |
| Karaoke Users | family | Karaoke Eternal |
| Caro Library Users | caro | Caro Tachidesk |
| Books Users | personal | BookOrbit |
| Uchiyomi Users | uchiyomi | Uchiyomi |
| Camera Viewers | personal | Frigate |
| Vaultwarden Users | personal | Vaultwarden |
| App Operators | operators (Paul only) | Caro Tachidesk, DDNS Updater, Frigate, Home Assistant, Karaoke Eternal, Mindwtr, Openfit, Prowlarr, qBittorrent, Radarr, SABnzbd, Shelfmark, Sonarr, Tachidesk, Vaultwarden, Z-Wave |

BookOrbit has its own confidential authorization-code client and supplied RSA
signer. Its only access binding is `Books Users`; it does not inherit the
operator group or assign BookOrbit roles from token claims. Keep the stable
`bookorbit` issuer and subject. Allow only the exact authorization callbacks
`https://books.diloreto.com/oauth2-callback` for browsers and
`bookorbit://oauth2-callback` for the native app.
Uchiyomi has a separate create-only OIDC application, client and signer in the
same authorities. `Uchiyomi Users` admits Paul, Carolyn and Eric; Uchiyomi
reads `App Operators` (Paul only) from the signed `profile` claim for its own
admin role. Uchiyomi X has a separate OIDC client and signer, and a single
standalone binding to the independently owned `paul` user. `App Operators`
maps Paul's in-app admin role, not access; neither another operator nor an
Authentik administrator gains access by group membership. These grants do not
alter Authentik administrator membership.
Removing any managed application/provider requires explicit reviewed destroy
actions, never orphaned state entries.

`App Operators` grants application access, not in-application administrator roles,
except when Shelfmark maps its trusted proxy group header or Uchiyomi maps its
signed OIDC group claim to its native admin role. Shelfmark is operator-only; no unauthenticated host port is published.
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
preserves the native export representation and adds the pinned reader's newline.
Imported material can retain a terminal newline in its native export, whereas
API-created material is trimmed on ingestion. Match the supplied public PEM and
encrypted private-key text to their respective exports; do not universally trim
existing signers or add an extra OpenSSL newline to new ones. Representation
qualification must prove identical certificate/key content and a fresh no-op plan,
not apply an unexplained rewrite. This does not rotate cryptographic material.

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

## Controller permissions

The owner-only [`authentik-access` OpenTofu root](../infrastructure/tofu/authentik-access)
owns the two controller roles, their declared global and object grants, and their
native [Initial Permissions](https://docs.goauthentik.io/users-sources/access-control/initial_permissions/).
The normal controller identities must not be able to modify these grants or write
their state. Verify all effective roles, including legacy assignments, before
claiming that boundary. Token issuance and role membership are independently bootstrapped: assign
`home-lab-opentofu-authentik-apply` only to `home-lab-opentofu-apply` and
`home-lab-opentofu-managed-group-read` (the shared refresh role) only to
`home-lab-opentofu-plan` and `home-lab-opentofu-apply`. Neither role may be
assigned to a group. Independently verify these assignments and all effective
grants; OpenTofu manages tracked grants, not the complete live role membership
or arbitrary grants added outside state. See [owner operations](operations.md#authentik-controller-permissions).

Applications have model-wide lifecycle grants. Other admitted models get global
`add` where needed and object-scoped writes. Existing objects get scoped grants
by the IDs pinned in [`desired.json`](../infrastructure/tofu/authentik/desired.json)
or independently adopted by exact ID. Initial Permissions gives newly created
objects their scoped grants automatically; the shared refresh role must already
be on the apply account when it creates them. Stock lookup dependencies and
provider-exposed singleton settings retain explicit permissions. New applications,
bindings, groups, providers and signers of an admitted type need no per-object
owner run. Adding a model is a reviewed access-root change.

Application-group membership and binding writes do not extend to Authentik admins.
Managed certificates allow private-key export to both controller accounts, not
for independently owned certificates. The shared refresh role has scoped OAuth
provider `change` because Authentik hides client secrets without it. The plan
credential is therefore mutating; see [security](security.md#opentofu-state-and-plans).
Blueprint writes, RBAC assignment, admin groups, controller roles and accounts,
and human users' write access are outside ordinary apply authority. Changes that
need role assignment or dedicated service-identity creation/removal (including
LDAP search-role grants) require independent owner review of the exact saved plan
and an owner-run apply; routine updates to the declared service accounts remain
object-scoped. Permission to delete is not approval to delete: inspect and
approve every destructive OpenTofu plan separately.
