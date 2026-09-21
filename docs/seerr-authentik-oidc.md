# Seerr and authentik OIDC

**Research cutoff:** 2026-09-20. This repository currently deploys Seerr `v3.4.1`.

## Conclusion

Authentik users can use Seerr through Seerr's native OIDC work, independently of Jellyfin authentication. However, OIDC is not included in the currently deployed stable `v3.4.1` release. The implementation remains an open preview pull request targeted at Seerr `v3.6.0`.

Authentik proxy authentication in front of Seerr is not equivalent: it authenticates the HTTP request at the proxy boundary but does not create a Seerr application session. Without native OIDC, users still encounter Seerr's own login.

## Current upstream state

- [Seerr PR #2715](https://github.com/seerr-team/seerr/pull/2715) adds OIDC provider buttons, callbacks, persistent linked accounts, optional automatic user creation, and unlinking. As of the cutoff it is open, labeled `preview` and `merge conflict`, and assigned to milestone `v3.6.0`.
- The PR says provider configuration is currently through `settings.json`; configuration UI, comprehensive documentation, and real-IdP end-to-end tests were not included in the review scope.
- Users may link OIDC to an existing Seerr account through **Linked Accounts**, preserving that account's request history and permissions. A provider may also enable `newUserLogin` to provision new accounts. Existing accounts should be linked before first OIDC login to avoid duplicate identities.
- The upstream [OIDC testing discussion](https://github.com/seerr-team/seerr/discussions/2721) contains successful Authentik reports. It also documents exact-issuer/trailing-slash sensitivity and separate callback URIs for login and linked-account operations.
- Stable release [`v3.4.1`](https://github.com/seerr-team/seerr/releases/tag/v3.4.1) predates this integration and does not include it.

## Recommendation

1. Keep stable Seerr `v3.4.1` for production today.
2. Treat Seerr OIDC as separate from Jellyfin OIDC: restoring Jellyfin's plugin does not automatically authenticate a Seerr session.
3. When Seerr `v3.6.0` or another stable release containing PR #2715 ships, configure a dedicated Authentik OIDC application/provider for Seerr.
4. Link existing Seerr accounts before enabling automatic OIDC user creation, then test request history, permissions, administrators, disabled users, logout, and rollback.
5. If access is urgent, test the digest-pinned preview against a copied Seerr configuration/database first; do not replace the production instance directly while the PR is open.

Until stable native OIDC ships, users need a Seerr local login or a credential path Seerr can validate through Jellyfin. Authentik forward-auth alone does not solve application login.
