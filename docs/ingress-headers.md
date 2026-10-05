# Public ingress headers

The public HTTPS entry point applies one HSTS policy to every routed host:
`Strict-Transport-Security: max-age=15552000`. It does not set
`includeSubDomains`, `preload`, or HSTS on the HTTP redirect entry point.

- [Nextcloud 34's security guidance](https://docs.nextcloud.com/server/34/admin_manual/installation/harden_server.html#enable-http-strict-transport-security) recommends HSTS to protect browsers against HTTP downgrade and certificate-warning bypass. It is a browser security policy, not a requirement for Nextcloud to serve requests. Keep the protection, but not a Nextcloud-only exception.
- [Traefik's entry point documentation](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/#httpmiddlewares) specifies that entry-point middlewares are prepended to every matching router and must use a provider-qualified name (`hsts@file`). Its [headers documentation](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/headers/) defines `stsSeconds` as the HSTS max-age; `stsIncludeSubdomains` and `stsPreload` default to false.
- Books routes directly to Grimmory with its native authentication and Traefik's standard forwarded headers. There is no Books-specific `X-Scheme` override or remote-auth header middleware. Verify HTTPS redirects and token-bearing Kobo download URLs on the actual routed application.

On deployment, verify public HTTPS responses for both Nextcloud and Books (and
other routed hosts) include HSTS, and that Books generates HTTPS links and
redirects. The controller test checks the declared policy, not live application
behavior. A future ingress or application update should recheck these assumptions.
