# Omada mail configuration

`secrets/omada-mail.sops.json` is the desired authority for Omada's SMTP
credentials, server, sender and alert recipients. SOPS encrypts every value to
both repository age recipients. Recover the age identity from independent
protected storage; ciphertext alone is not sufficient for recovery.

The input contract is validated by native jq in
[`omada-mail-input.jq`](../scripts/omada-mail-input.jq):

- `schema_version`: `1`.
- `smtp`: `host`, integer `port`, `security` (`starttls` or `tls`),
  `username`, `password` (the dedicated SMTP token), and `sender`.
- `recipients`: a nonempty list of unique recipient email addresses.

Use a dedicated Omada SMTP token, not an account login password or another
application's token. For Proton, pair the token with a custom-domain address
and use that address for both username and sender. Its submission transport is
`smtp.protonmail.ch:587` with STARTTLS. Do not revoke an old token until a
separately approved rotation has been applied and delivery verified.

## Capture and validate without applying

Initial capture uses a private, per-run wizard outside Git. It prompts for the
username and token with hidden input, defaults the recipient to
`paul@diloreto.com`, and writes only ciphertext into `secrets/`. It does not
change the controller, send email, stage files or commit. Temporary plaintext
capture files are mode 0600 inside a mode-0700 directory and removed on exit.
Do not run with shell tracing, terminal recording or a shared terminal.

For subsequent edits, use native SOPS in a protected local editor:

```sh
sops secrets/omada-mail.sops.json
scripts/check-omada-mail
python3 scripts/test-omada-mail.py
```

The checker requires the protected age identity and validates decrypted input
in a pipe without printing values or writing plaintext under Git. Review the
ciphertext and configuration tooling separately from live activation.

## Activation boundary

This setup path **stages desired input only**. It neither configures SMTP nor
enables notification delivery. Applying it requires a separately reviewed
controller configuration step and a successful test email to the intended
recipient before declaring delivery functional.

The pinned `mbentley/omada-controller` image does not document an SMTP
password-file or `_FILE` reader. Do not invent an environment variable or add
an ineffective Compose secret mount. Omada persists SMTP settings in its own
controller data; that data remains sensitive and belongs in the existing
protected backup/recovery scope. SOPS remains the desired credential authority,
not a second plaintext copy in Compose's interpolation environment.

The Omada OpenTofu provider manages alert/event delivery toggles, but not the
SMTP server, SMTP credential or recipient list. Keep their controller
configuration separate from provider adoption. For Omada STARTTLS, its native
SSL checkbox is **off**; it is **on** for implicit TLS. Do not confuse this
with disabling HTTPS certificate verification for the management API.

## Primary sources

- [Proton SMTP submission and dedicated tokens](https://proton.me/support/smtp-submission).
- [TP-Link SMTP encryption, including STARTTLS](https://www.tp-link.com/us/support/faq/3260/).
- [Image configuration interfaces](https://github.com/mbentley/docker-omada-controller#optional-environment-variables).
- [Pinned provider notification coverage](https://github.com/wncservices/terraform-provider-omada/blob/v0.11.10/docs/resources/notification_settings.md).
