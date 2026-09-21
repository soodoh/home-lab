# Research: Authentik-backed login options for Jellyfin 12.1

**Research cutoff:** 2026-09-20 (inclusive)  
**Scope:** Jellyfin Server 12.1, authentik, and authentication plugins. Only first-party project material—official documentation, source repositories, issue/PR records, releases, and manifests—was used. “First-party” for an independent plugin means its own repository and manifest; this does not make the plugin an official Jellyfin component.

## Summary

Jellyfin 12.1 has neither released native OIDC/OAuth2 login nor released native trusted-header login. A native OIDC implementation exists only as an open, unreviewed server PR and Jellyfin maintainers prefer that functionality to live in a plugin. Authentik forward-auth can protect the HTTP boundary, but without a Jellyfin 12-compatible trusted-header bridge it cannot create a Jellyfin user/session and is especially unsuitable as the only gate for native clients.

**Production recommendation:** use authentik’s LDAP Outpost with the official Jellyfin **LDAP Authentication 24.0.0.0** plugin as the conservative immediate restoration path. It is the only official, published Jellyfin-12 ABI build in this comparison and works through Jellyfin’s normal credential UI on browser and native clients. It is not browser SSO and has weaker UX/security properties than OIDC. Stage Flowfin separately, but do not make its current 5.0 beta the production login path yet: its own 2026-09-20-era release note explicitly says it has not had a manual release-QA pass on live Jellyfin 12 GA and says to use it for testing, not production. Flowfin is not the only realistic OIDC option: aussierk’s independently developed OIDC plugin has a Jellyfin-12 stable-channel build, but it was only three days old at cutoff and lacks equivalent demonstrated live-Jellyfin/provider-matrix evidence in the inspected primary material.

## Findings

### 1. Jellyfin 12.1 has no released native OIDC/OAuth2 or trusted-header authentication

1. **Claim:** Jellyfin 12.1 does not ship native OIDC/OAuth2 login. **Sources:** [Jellyfin 12.1 release](https://github.com/jellyfin/jellyfin/releases/tag/v12.1), [native OIDC PR #17271](https://github.com/jellyfin/jellyfin/pull/17271). **Support:** direct evidence. **Confidence:** high.
   - The 12.1 changelog contains no OIDC feature.
   - PR #17271 was still **open**, had no review verdict, and had no milestone at cutoff. A Jellyfin maintainer stated on 2026-09-16 that the 6,000+ line core change was too large a maintenance burden and that authentication is accessible to plugins, making a plugin the preferred path.
   - The PR’s proposed v1 also explicitly omits stored upstream tokens, RP-initiated upstream logout, OIDC session metadata, and device authorization. Even if later merged, those are relevant initial limitations.

2. **Claim:** Jellyfin 12.1 has no native mechanism that trusts an upstream identity header and turns it into a Jellyfin application session. **Sources:** [Jellyfin issue #1403](https://github.com/jellyfin/jellyfin/issues/1403), [external-auth-gateway issue #16956](https://github.com/jellyfin/jellyfin/issues/16956), [HttpAuth project](https://github.com/UlysseM/jellyfin-plugin-httpauth), [HttpAuth manifest](https://raw.githubusercontent.com/UlysseM/jellyfin-plugin-httpauth/gh-pages/repository.json). **Support:** direct evidence plus source interpretation. **Confidence:** high.
   - Jellyfin’s core still performs its own application authentication. Issue #16956 documents the mismatch between a browser-oriented external gate and native Jellyfin clients.
   - HttpAuth demonstrates that a plugin can translate a trusted header into Jellyfin authentication, but its latest published build targets ABI **10.11.10.0**, not 12.0.0.0.

3. **Claim:** “It compiles/loads on Jellyfin 12” is not the same as “production ready.” **Sources:** [Jellyfin 12.0 release notes](https://jellyfin.org/posts/jellyfin-release-12.0/), [Flowfin releases](https://github.com/Flowfin/jellyfin-plugin-sso/releases). **Support:** direct evidence. **Confidence:** high.
   - Jellyfin 12 moved to .NET 10 and changed plugin interfaces; Jellyfin explicitly says 10.11 plugins must be retargeted and rebuilt.
   - A manifest `targetAbi: 12.0.0.0` establishes intended ABI selection, not manual end-to-end QA, security review, operational maturity, or native-client coverage.

### 2. Flowfin Community SSO: compatible beta and closest 9p4 successor, but not production-ready at cutoff

4. **Claim:** Flowfin is a security-focused continuation of archived `9p4/jellyfin-plugin-sso`; its 5.x line targets Jellyfin 12/.NET 10, while 4.3.0 is the final Jellyfin 10.11 line. **Sources:** [Flowfin repository/README](https://github.com/Flowfin/jellyfin-plugin-sso), [Flowfin beta manifest](https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/manifest-beta/manifest.json). **Support:** direct evidence. **Confidence:** high.
   - The current manifest advertises plugin GUID `505ce9d1-d916-42fa-86ca-673ef241d7df` and `targetAbi: 12.0.0.0` for the 5.0 Jellyfin-12 line.
   - **Migration:** Flowfin says the GUID is unchanged from 9p4, so installing it over the old plugin preserves the plugin identity and configuration. This is the lowest-friction continuation path, but a pre-change backup and configuration review remain mandatory; GUID continuity does not prove every legacy option has identical semantics.

5. **Claim:** The only Flowfin release channel available at cutoff is beta. **Sources:** [Flowfin README](https://github.com/Flowfin/jellyfin-plugin-sso), [beta manifest](https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/manifest-beta/manifest.json), [releases](https://github.com/Flowfin/jellyfin-plugin-sso/releases). **Support:** direct evidence. **Confidence:** high.
   - Repository URL: `https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/manifest-beta/manifest.json`.
   - The project says a stable channel will open with its first stable release. The inspected current build was plugin **5.0.0.88**, published as a prerelease.

6. **Claim:** Flowfin has unusually substantial automated security/release engineering for an independent plugin, but its own release gate was incomplete. **Sources:** [Flowfin repository](https://github.com/Flowfin/jellyfin-plugin-sso), [5.0 beta release notes](https://github.com/Flowfin/jellyfin-plugin-sso/releases), [security policy](https://github.com/Flowfin/jellyfin-plugin-sso/security). **Support:** direct evidence. **Confidence:** high.
   - Source includes unit tests and CI workflows for build, CodeQL, dependency review, fuzzing, mutation testing, OpenGrep, OpenSSF Scorecard, Unicode checks, manifest verification, performance baseline, and end-to-end login.
   - Its publish gate boots `jellyfin/jellyfin:12.0`, installs the shipped net10 artifact, and drives OIDC/SAML round trips across seven IdP stacks.
   - **Decisive contrary evidence:** the release notes state that the 5.0/JF12 line had **no manual Release-QA pass against live Jellyfin 12 GA**, was outside the 4.x release-candidate gate, and should be used “for testing, not production.” Automated login success establishes more than ABI compatibility but still does not close manual browser/native-client and upgrade/rollback validation.

7. **Claim:** Flowfin materially hardens the old design, but changes the risk surface and must be configured fail-closed. **Sources:** [Flowfin README](https://github.com/Flowfin/jellyfin-plugin-sso), [Flowfin repository source](https://github.com/Flowfin/jellyfin-plugin-sso). **Support:** direct evidence. **Confidence:** medium-high.
   - Advertised controls include stable `sub`/NameID identity binding, fail-closed token/assertion validation, SSRF-guarded avatar fetching, account linking, role/group mapping, rate limiting/replay handling, protected secrets, last-admin protections, and an optional SSO-only mode with a designated break-glass administrator.
   - Recent release entries show fixes specifically preventing self-unlink/revoke paths that could strand an administrator and refusing a break-glass account whose only password was minted by the plugin. These are valuable controls but also evidence that lockout invariants were still actively changing immediately before cutoff.

8. **Claim:** Authentik OIDC configuration is straightforward, but exact redirects and claims must be treated as deployment-specific data rather than guessed. **Sources:** [authentik Jellyfin integration guide](https://docs.goauthentik.io/integrations/services/jellyfin/), [authentik OAuth2/OIDC provider docs](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/), [Flowfin provider documentation entry point](https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Provider-Setup). **Support:** direct evidence and implementation guidance. **Confidence:** medium-high.
   - Create a confidential OAuth2/OpenID provider/application in authentik; register an **exact** HTTPS redirect URI. Authentik’s Jellyfin guide uses `https://<jellyfin>/sso/OID/redirect/authentik`, and discovery at `https://<authentik>/application/o/jellyfin/.well-known/openid-configuration`.
   - Configure the plugin’s provider name consistently with the redirect suffix, client ID/secret, issuer/discovery URL, and claims/groups. Select an authentik signing certificate so JWTs use an asymmetric algorithm such as RS256; authentik documents that no signing key means HS256 with the client secret and no public JWKS key.
   - Grant only an explicit Jellyfin access group and map least privilege; never infer administrator from broad authentik membership. Test discovery/JWKS and callback reachability server-to-server.
   - **Unknown:** the exact Flowfin 5.0 UI defaults and every required scope/property mapping were not independently captured in the inspected pages. Follow the version-matched Flowfin wizard/wiki and the callback it displays, not a copied legacy recipe.

9. **Claim:** Flowfin browser login is the primary SSO experience; native applications generally need Jellyfin Quick Connect rather than running the OIDC redirect themselves. **Sources:** [Flowfin README](https://github.com/Flowfin/jellyfin-plugin-sso), [Flowfin releases](https://github.com/Flowfin/jellyfin-plugin-sso/releases), [Jellyfin Quick Connect docs](https://jellyfin.org/docs/general/server/quick-connect/). **Support:** direct evidence. **Confidence:** high.
   - Flowfin says sign-in works in Jellyfin Web and, through Quick Connect, native clients.
   - Its final 4.3 release explicitly says Android and Android TV Quick Connect round trips were not manually exercised; the 5.0 release says no manual live-JF12 QA pass occurred. Therefore individual client behavior—TV input, mobile deep links, Swiftfin, casting, and logout—is **not production-verified by the cited release evidence**.
   - Clients without Web-UI injection or Quick Connect cannot use the SSO button. OIDC logout and Jellyfin logout should not be assumed to terminate all IdP/Jellyfin sessions unless explicitly tested.

### 3. Authentik Proxy Provider / forward-auth protects the boundary but does not log into Jellyfin

10. **Claim:** Authentik forward-auth authorizes each HTTP request at the reverse-proxy boundary; it does not itself create Jellyfin’s application token/session. **Sources:** [authentik forward-auth docs](https://docs.goauthentik.io/add-secure-apps/providers/proxy/forward_auth/), [Jellyfin external-gateway issue #16956](https://github.com/jellyfin/jellyfin/issues/16956), [HttpAuth implementation](https://github.com/UlysseM/jellyfin-plugin-httpauth). **Support:** direct evidence plus source interpretation. **Confidence:** high.
    - Authentik states that application traffic continues to the upstream application while the outpost only checks authentication/authorization. It can return `X-authentik-*` headers, but Jellyfin does not consume those as a login protocol.
    - Result without a bridge: a browser authenticates to authentik and then still reaches Jellyfin’s login page. Native API/WebSocket/media requests may be redirected to HTML or rejected because native clients generally cannot complete that external browser flow.
    - A boundary gate can be an additional defense for an admin-only hostname or browser-only route, but it is not a substitute for Jellyfin authentication.

11. **Claim:** No maintained, published Jellyfin-12 trusted-header bridge was verified at cutoff. **Sources:** [HttpAuth repository](https://github.com/UlysseM/jellyfin-plugin-httpauth), [HttpAuth manifest](https://raw.githubusercontent.com/UlysseM/jellyfin-plugin-httpauth/gh-pages/repository.json), [abandoned predecessor linked by HttpAuth](https://github.com/pikami/jellyfin-header-auth). **Support:** direct evidence. **Confidence:** high.
    - HttpAuth 1.1.3 was active in June 2026 but targets Jellyfin ABI 10.11.10.0 and its source design mutates/injects the web `index.html`, then performs a synthetic login through an authentication provider.
    - Its author warns that any direct path to Jellyfin, or failure to overwrite the identity header, permits impersonation—including administrator impersonation. That design should not be locally rebuilt for 12 and called production-ready without upstream release/QA.
    - `pikami/jellyfin-header-auth` is described by the maintained project as never working and abandoned; reject it.

### 4. Authentik LDAP Outpost plus official Jellyfin LDAP plugin is the conservative production path

12. **Claim:** The official Jellyfin catalog publishes **LDAP Authentication 24.0.0.0**, timestamped 2026-09-08, with `targetAbi: 12.0.0.0`. **Sources:** [official Jellyfin plugin manifest](https://repo.jellyfin.org/files/plugin/manifest.json), [official LDAP plugin repository](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [official releases](https://github.com/jellyfin/jellyfin-plugin-ldapauth/releases). **Support:** direct evidence. **Confidence:** high.
    - Do not confuse plugin version 24 with old plugin version 12.0.0.0, which targeted Jellyfin 10.7.
    - Version 24’s manifest notes the Jellyfin-preview update and LDAP admin-filter username-resolution fix. Official publication and ABI targeting make it the strongest production signal here, not a guarantee of defect-free operation.

13. **Claim:** Authentik officially documents LDAP Outpost integration with Jellyfin’s LDAP plugin. **Sources:** [authentik Jellyfin guide](https://docs.goauthentik.io/integrations/services/jellyfin/), [authentik LDAP provider docs](https://docs.goauthentik.io/add-secure-apps/providers/ldap/), [Jellyfin LDAP plugin README](https://github.com/jellyfin/jellyfin-plugin-ldapauth). **Support:** direct evidence. **Confidence:** high.
    - Deploy an LDAP-type outpost, attach a Jellyfin-scoped LDAP application/provider, use a unique Base DN, and prefer LDAPS/StartTLS with certificate and TLS server-name validation.
    - Jellyfin needs a search/service identity with access to the application and permission to search the required directory scope. Use a narrowly scoped authentik service account and app password, not an API token; grant object-level “Search full LDAP directory” only on this provider where feasible.
    - Configure Jellyfin’s LDAP server/TLS, bind DN/password, base user DN, username/search attributes, and a required restrictive user filter/group. Authentik exposes usernames as `cn`, unique IDs as `uid`, email as `mail`, and group membership as `memberOf`.
    - Keep automatic administrator assignment off initially. The plugin describes its admin filter as being applied on user creation; it is not a substitute for deliberate local admin management.

14. **Claim:** LDAP works through Jellyfin’s ordinary login UI and therefore has the broadest browser/native-client compatibility, but it is not OIDC SSO. **Sources:** [LDAP plugin README](https://github.com/jellyfin/jellyfin-plugin-ldapauth), [authentik LDAP docs](https://docs.goauthentik.io/add-secure-apps/providers/ldap/). **Support:** direct evidence and interpretation. **Confidence:** high.
    - Users enter an authentik-backed username/password into Jellyfin; there is no browser redirect, IdP session reuse, consent, or upstream single logout.
    - The user credential transits Jellyfin and the LDAP channel, so verified LDAPS and secret/log hygiene matter. OIDC instead keeps primary authentication at authentik and gives Jellyfin signed protocol assertions.
    - Authentik can enforce Duo/TOTP/static-code MFA for LDAP via `password;code`, but not WebAuthn or SMS; this is an awkward native-client UX. App passwords can satisfy the password stage but other flow policies still apply.
    - Prefer **direct bind** for timely revocation. Authentik warns cached-bind results remain valid in outpost memory despite session revocation or credential changes; cached search can also return stale directory data.
    - Local Jellyfin accounts remain the practical break-glass mechanism. This is a benefit during rollout, but it means LDAP is federation of credentials, not universal password elimination.

### 5. Other Jellyfin-12 OIDC alternatives

15. **Claim:** `aussierk/jellyfin-plugin-oidc` is a real maintained Jellyfin-12 OIDC alternative and disproves “Flowfin is the only option,” but its production evidence was immature at cutoff. **Sources:** [project repository](https://github.com/aussierk/jellyfin-plugin-oidc), [published manifest](https://raw.githubusercontent.com/aussierk/jellyfin-plugin-oidc/main/manifest.json), [migration guide](https://github.com/aussierk/jellyfin-plugin-oidc/blob/main/MIGRATION.md). **Support:** direct evidence. **Confidence:** medium-high.
    - Stable-channel version **2.1.0.1**, timestamped 2026-09-18, targets ABI 12.0.0.0. The source includes extensive unit tests and advertises authorization-code + PKCE, subject-keyed identity, fail-closed RBAC, endpoint pinning/SSRF/DNS-rebinding defenses, Quick Connect, back-channel logout, and client-secret indirection.
    - It has a different GUID (`e1c020c5-3972-4b7b-9538-ee4934cc902c`) and its migration guide is about matching/reclaiming Jellyfin users—not in-place migration of 9p4 configuration. Installing it does not preserve the 9p4 plugin config by GUID.
    - **Researcher inference:** this may become the better OIDC design for an OIDC-only deployment, but at cutoff the JF12 stable rewrite was one to three days old. The inspected first-party material did not demonstrate Flowfin-like live-Jellyfin seven-provider release gating or a manual native-client matrix. Treat it as a lab candidate, not the immediate production choice.

16. **Claim:** K0lin’s fork is not a production alternative at cutoff. **Sources:** [K0lin repository](https://github.com/K0lin/jellyfin-plugin-sso). **Support:** direct evidence. **Confidence:** high.
    - It supports Jellyfin 12 from 5.1 and Web UI/Quick Connect clients, but its own README labels it **“100% alpha software”**, warns of permission overwrite/demotion behavior, notes no logout callback, and says nightlies may break or lose data. Reject for this home lab’s production path.

17. **Claim:** No other maintained, verified Jellyfin-12 trusted-header/OIDC project should be selected from the inspected primary-source set. **Sources:** the manifests/repositories cited above. **Support:** source interpretation. **Confidence:** medium.
    - MaxRink’s PR comment referenced a release candidate fork, but an ad-hoc RC named in a discussion is not sufficient maintenance/release evidence.
    - Abandoned header projects, Jellyfin-10.11-only builds, source-only ports, and projects without a verifiable `targetAbi: 12.0.0.0` artifact were excluded.

## Ranked recommendation

| Rank | Path | Recommendation at cutoff | Why |
|---:|---|---|---|
| 1 | Authentik LDAP Outpost + official LDAP Authentication 24.0.0.0 | **Deploy conservatively** | Official Jellyfin catalog/source, explicit ABI 12 build, documented by authentik, works with normal native clients. Tradeoff: credentials rather than browser SSO; weaker MFA/SSO UX. |
| 2 | Flowfin Community SSO 5.0 beta | **Stage and qualify; do not yet make production-exclusive** | Best 9p4 lineage/config continuity and strongest observed automated provider/security QA, but beta-only and explicitly “testing, not production” pending manual JF12 GA QA. |
| 3 | aussierk SSO-OIDC 2.1.0.1 | **Parallel lab evaluation only** | Credible maintained OIDC-only alternative with stable manifest and strong design claims, but very new JF12 rewrite and no in-place 9p4 config migration or equivalent observed release-validation evidence. |
| 4 | Authentik forward-auth alone | **Do not use as login restoration** | Protects HTTP boundary only; does not mint Jellyfin session/token and impairs native clients. |
| 5 | K0lin / HttpAuth / abandoned header forks | **Reject for production** | Alpha, wrong ABI, or abandoned/unverified. |

## Guarded rollout plan for this home lab

1. **Freeze and inventory.** Record Jellyfin 12.1, installed plugin folders/versions, current authentication-provider settings, usernames (including exact case), user IDs, admin flags, library policies, current 9p4/Flowfin XML/config, reverse-proxy routes, and authentik groups. Do not delete the old plugin config.
2. **Back up before any plugin/auth change.** Stop Jellyfin and take a full manual backup of its data/config/plugin directories. Confirm the repository’s normal recovery/restore procedure and obtain the ordinary deployment authority before changing the running service. A plugin uninstall is not an adequate rollback for config/database changes.
3. **Prove break glass first.** Create or verify a dedicated, non-SSO **local Jellyfin administrator** with a strong unique password. Confirm it in a private browser with authentik unavailable and via an internal/Tailscale-restricted origin that bypasses any external forward-auth gate. Do not reuse this username in authentik; do not migrate/link it; do not let LDAP/OIDC admin-group synchronization touch it. Store the credential in the existing secret-management process.
4. **Build LDAP beside local auth.** Deploy an authentik LDAP Outpost and Jellyfin-scoped provider/application. Use LDAPS with certificate validation, direct bind, direct search initially, a narrowly authorized service account/app password, and a restrictive access-group filter. Install official LDAP Authentication **24.0.0.0** only from Jellyfin’s catalog and restart.
5. **Pilot without admin automation.** Test one non-admin account first. Disable LDAP automatic user creation initially if practical; otherwise constrain the LDAP filter to a small pilot group. Verify existing-user matching, new-user defaults, disabled-user behavior, library restrictions, password changes/revocation, logs, Web, Android/iOS/TV clients, playback, WebSockets, Quick Connect, and outage behavior. Confirm the local admin still works after every step.
6. **Expand LDAP gradually.** Add users/groups in batches. Keep at least two independently tested administrative paths during the observation window. Avoid authentik cached bind until its stale-revocation behavior is explicitly accepted.
7. **Stage Flowfin on a restored clone or isolated test Jellyfin first.** Pin an exact 5.0 beta artifact/checksum rather than floating to nightly updates. Restore the old 9p4 configuration into that clone and verify that same-GUID migration preserves—not merely loads—the provider, claims, roles, account links, and policies. Configure authentik with the callback URI displayed by that exact build, RS256, exact redirect matching, least-privilege access group, and no SSO-only switch.
8. **Run the missing manual QA locally.** Test browser login/link/unlink/logout, authentik MFA, expired/revoked/disabled users, issuer/audience/nonce/state failures, key rotation, IdP outage, Jellyfin restart, reverse-proxy base URL, Android/iOS/TV Quick Connect, a client with no Quick Connect, and rollback. Verify account IDs/watch history and that no role mapping can promote or demote the break-glass admin.
9. **Promotion gate for Flowfin:** require an upstream stable JF12 channel or an upstream declaration that its live-JF12 manual release checklist passed, plus this lab’s tests and an observation period. Until then LDAP remains production authentication. If Flowfin is promoted, migrate one non-admin account at a time and keep local password login/LDAP available; enable SSO-only only after an independently tested rollback—and exempt only the dedicated break-glass admin.
10. **Do not place global forward-auth in front of all Jellyfin routes.** If used at all, scope it to a browser/admin-only hostname or route after testing; never expose an upstream identity header from clients, and firewall Jellyfin so only the reverse proxy can reach any future header-auth bridge.
11. **Rollback:** revert the deployment/config through the repository’s normal convergence path, restore the full stopped-service backup if plugin/config/database state changed incompatibly, remove only the new authentik application/outpost after Jellyfin local access is confirmed, and retest the break-glass origin. Do not attempt downgrade with a 10.11 plugin binary on Jellyfin 12.

## Contradictions

1. **Flowfin appears highly engineered but says not to use its JF12 build in production.** Its repository advertises extensive hardening and automated seven-provider live-Jellyfin tests; its release note simultaneously states no manual GA Release-QA pass and explicitly says “testing, not production.” These statements are complementary, not evidence that the beta is production-ready. [Repository](https://github.com/Flowfin/jellyfin-plugin-sso), [releases](https://github.com/Flowfin/jellyfin-plugin-sso/releases).
2. **“Stable channel” does not establish maturity across projects.** aussierk publishes 2.1.0.1 in its stable manifest, while Flowfin retains beta naming despite broader observed automated integration coverage. Channel labels are project-local; compare evidence, age, migration behavior, and QA rather than labels alone. [aussierk manifest](https://raw.githubusercontent.com/aussierk/jellyfin-plugin-oidc/main/manifest.json), [Flowfin releases](https://github.com/Flowfin/jellyfin-plugin-sso/releases).
3. **The official authentik Jellyfin guide references the historic SSO-Auth integration, while that original plugin was archived.** The OIDC endpoints/configuration model remains relevant, but plugin installation guidance must be replaced with the chosen maintained plugin’s version-specific instructions. [authentik guide](https://docs.goauthentik.io/integrations/services/jellyfin/), [Flowfin repository](https://github.com/Flowfin/jellyfin-plugin-sso).

## Missing evidence

- No Flowfin 5.0 manual release-QA pass on live Jellyfin 12 GA existed in the cited release evidence at cutoff; individual native-client behavior is therefore unverified.
- No independent audit or production incident history was found for Flowfin or aussierk. CI/security controls are not an audit.
- The inspected primary material did not establish whether Flowfin 5.0.0.88 had any currently open security defects; absence of a cited advisory is not proof of absence.
- Exact current home-lab Jellyfin/authentik/reverse-proxy configuration, account naming, client mix, and restore evidence were not inspected. These determine migration and lockout risk.
- The exact version-matched Flowfin authentik scopes/property mappings and all migrated 9p4 configuration semantics need hands-on verification from the build’s UI/wiki.
- The official LDAP plugin manifest proves ABI targeting, not a manual Jellyfin-12/Authen­tik matrix. Its version-24 user/login/admin-filter behavior should be tested locally.
- No released Jellyfin-12 trusted-header plugin was verified. This can change after the cutoff.

## Sources

### Kept

- [Jellyfin 12.0 release notes](https://jellyfin.org/posts/jellyfin-release-12.0/) — authoritative ABI/plugin migration warning.
- [Jellyfin Server 12.1 release](https://github.com/jellyfin/jellyfin/releases/tag/v12.1) — authoritative shipped feature set.
- [Jellyfin native OIDC PR #17271](https://github.com/jellyfin/jellyfin/pull/17271) — status, proposed scope/limitations, validation, and maintainer direction.
- [Jellyfin external-gateway issue #16956](https://github.com/jellyfin/jellyfin/issues/16956) — first-party record of native-client gateway limitations.
- [Flowfin repository](https://github.com/Flowfin/jellyfin-plugin-sso) — lineage, feature claims, GUID migration, channel and test structure.
- [Flowfin releases](https://github.com/Flowfin/jellyfin-plugin-sso/releases) — decisive QA/readiness statement and current prerelease.
- [Flowfin beta manifest](https://raw.githubusercontent.com/Flowfin/jellyfin-plugin-sso/manifest-beta/manifest.json) — GUID, ABI, artifact and release metadata.
- [authentik Jellyfin integration guide](https://docs.goauthentik.io/integrations/services/jellyfin/) — official LDAP/OIDC integration topology and endpoint pattern.
- [authentik forward-auth docs](https://docs.goauthentik.io/add-secure-apps/providers/proxy/forward_auth/) — authoritative boundary-auth semantics.
- [authentik LDAP provider docs](https://docs.goauthentik.io/add-secure-apps/providers/ldap/) — schema, TLS, bind/search, MFA and cache semantics.
- [authentik OAuth2/OIDC provider docs](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/) — flow, redirect, PKCE and signing guidance.
- [Official Jellyfin plugin manifest](https://repo.jellyfin.org/files/plugin/manifest.json) — LDAP 24 artifact, timestamp and ABI.
- [Official Jellyfin LDAP plugin](https://github.com/jellyfin/jellyfin-plugin-ldapauth) — behavior and maintenance source.
- [aussierk OIDC repository](https://github.com/aussierk/jellyfin-plugin-oidc) and [manifest](https://raw.githubusercontent.com/aussierk/jellyfin-plugin-oidc/main/manifest.json) — maintained alternative, design and JF12 release metadata.
- [K0lin SSO repository](https://github.com/K0lin/jellyfin-plugin-sso) — project’s own alpha/limitations statement.
- [HttpAuth repository](https://github.com/UlysseM/jellyfin-plugin-httpauth) and [manifest](https://raw.githubusercontent.com/UlysseM/jellyfin-plugin-httpauth/gh-pages/repository.json) — trusted-header mechanism, warning, and incompatible ABI evidence.

### Rejected/deprioritized

- Reddit, forums, NewReleases, blogs, and aggregators — not primary sources.
- `pikami/jellyfin-header-auth` — abandoned/unverified and superseded by the maintained project’s own discussion.
- MaxRink release candidate mentioned in a PR comment — insufficient maintained release/channel evidence for production selection.
- JellyfinSecurity and unrelated proxy products — not needed to answer the application-session question and not a maintained Jellyfin-12 SSO solution verified here.

## Next steps

1. Inspect the actual home-lab Jellyfin plugin/config volume, reverse-proxy reachability, authentik deployment, client inventory, and last successful restore evidence without revealing secrets.
2. Recheck Flowfin’s JF12 release notes after the cutoff for a completed manual QA gate/stable channel.
3. Build a disposable restored clone and execute the rollout test matrix before choosing whether LDAP remains long-term or Flowfin is promoted.
