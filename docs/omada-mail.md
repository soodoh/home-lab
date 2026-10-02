# Omada mail configuration

`secrets/omada-mail.sops.json` is the desired authority for SMTP credentials,
server, sender and the selected site's required alert recipients. SOPS encrypts every
value to both repository age recipients. Recover the age identity from independent
protected storage; ciphertext alone is not sufficient for recovery.

The [native jq input contract](../scripts/omada-mail-input.jq) requires:

- `schema_version`: `1`.
- `smtp`: `host`, integer `port`, `security` (`starttls` or `tls`),
  `username`, `password` (a dedicated SMTP token), and `sender`.
- `recipients`: a nonempty list of unique recipient email addresses.
- Username and token: visible ASCII, 1–128 characters, matching the native form.

Use a dedicated Omada SMTP token, not an account password or another application's
token. For Proton, pair the token with a custom-domain address and use that address
for both username and sender. Submission is `smtp.protonmail.ch:587` with STARTTLS.
Omada's SSL checkbox is **off** for STARTTLS and **on** for implicit TLS; this does
not disable management-API HTTPS certificate verification. The transport mapping
follows TP-Link's guidance, not an independent SMTP downgrade-resistance audit.

## Capture and validate

Initial capture uses a private, per-run wizard outside Git. It captures credentials
with hidden input, defaults the recipient to `paul@diloreto.com`, and writes only
ciphertext into `secrets/`. It does not change the controller, send email, stage
files or commit. Temporary plaintext files are mode 0600 in a mode-0700 directory
and removed on normal exit or handled interruption. Do not enable shell tracing,
terminal recording or shared-terminal access.

For subsequent edits, use native SOPS in a protected local editor:

```sh
sops secrets/omada-mail.sops.json
scripts/check-omada-mail
python3 scripts/test-omada-mail.py
python3 scripts/test-omada-mail-convergence.py
```

The checker requires the protected age identity and validates decrypted input in
a pipe without printing values or writing plaintext under Git. Convergence tests
exercise native Ansible tasks against a synthetic loopback HTTPS controller; they
never use production credentials or deliver real email.

## Recipient ownership prerequisite

On controller `6.3.0.45`, notification `recipients` is a **read-only projection**
of administrator account email addresses and their alert subscriptions. The native
log UI disables direct recipient editing and sends “Manage Recipients” to accounts.
A notification PATCH can return success while ignoring a supplied recipient list.
Do not use that PATCH to configure recipients.

Account identity, email, alert subscriptions, privileges and site access remain
independently owned. Configure a reviewed existing account through its native
account interface only after separate owner approval; do not create an account,
change credentials/roles/site grants, or subscribe provider service accounts merely
to satisfy mail admission. Requalify the account interface before adding automation.

SOPS `recipients` is the required destination set, not an account-writing grant.
The SMTP role observes the selected site and requires its account-derived recipient
set to match exactly before convergence. Missing or unexpected destinations refuse
both the preview and apply **before any SMTP write**. The playbook runs this
read-only prerequisite before acquiring production ownership, then rereads under
ownership. The observer still reports differences without changing anything.

## Observe without applying

Start from a clean reviewed checkout and a **fresh private provider session** using
[operations](operations.md#prepare-a-disposable-controller). Supply
`SOPS_AGE_KEY_FILE` from protected storage and export
`HOME_LAB_PROVIDER_SESSION_DIR` with the new plan/apply credential files. The role
refuses stale, unowned, symlinked or unprotected credentials. It uses the reviewed
HTTPS origin, normal system certificate trust, no proxy and no redirects. It
refuses unqualified controller versions and absent or ambiguous sites.

```sh
export ANSIBLE_CONFIG=ansible/ansible.cfg
ansible-playbook ansible/playbooks/observe-omada-mail.yml
ansible-playbook ansible/playbooks/converge-omada-mail.yml --check
```

The observer is read-only even without `--check`: authentication creates a session,
but no configuration PATCH or test-email submission is permitted. Check mode uses
only the plan identity and reports bounded SMTP change decisions and recipient
prerequisite status. A missing recipient is not an SMTP-side update to apply.
The convergence playbook additionally observes host, Compose and backup admission;
check mode does not acquire a production mutation lock.

**The controller masks the SMTP token.** Public-settings convergence is not proof
that the stored token matches SOPS. A normal run does not repeatedly rewrite an
unreadable credential. A token-only rotation requires the explicit rotation flag.

## Approved activation or rotation

This source interface is not an apply approval. Review fresh observation and the
entire intended change, then explicitly approve application. The playbook acquires
the existing Docker-host production lock and reobserves Compose before API writes.
Do not run OpenTofu notification changes, account subscription changes or manual
controller edits concurrently. A reread refuses already-visible edits, but cannot
eliminate the final read/write race.

After separate approval, the invocation shape is:

```sh
ansible-playbook ansible/playbooks/converge-omada-mail.yml \
  -e omada_mail_apply_confirmed=true -e omada_mail_send_test=true
```

For an approved **token-only** rotation, also pass
`-e omada_mail_rotate_credentials=true`. Keep the previous token valid and its SOPS
revision recoverable until delivery with the new token has been verified.

The role writes **only controller-wide SMTP**. It never writes the notification
document, account records, recipients, IGMP settings, Compose configuration or
OpenTofu state. It verifies every observed notification toggle, delivery flag,
delay, webhook selection and unmodelled field is unchanged, excluding only dynamic
controller-owned `resource` metadata. The provider remains the owner of adopted
notification toggles; native accounts own recipient projection.

After writes, the role rereads and verifies public SMTP settings, recipients and
all preserved notification fields. Tests are opt-in, one submission per desired
recipient, using reread form settings and the native stored-password sentinel,
not a desired token supplied as a transient test credential. API success means
**submission accepted**, not confirmed mailbox delivery. Independently check receipt
and require a fresh observer/check before declaring mail functional. Writes and
sentinel behavior need independent live qualification; successful SMTP persistence
alone does not qualify test submission or delivery. Synthetic tests are not that
evidence.

Failure retains the production lock. Reobserve controller and host state, keep
private evidence and resolve the retained owner using the existing independently
reviewed lock-clear procedure. Do not automatically roll back or revoke credentials.

## Secret delivery boundary

The pinned `mbentley/omada-controller` image has no documented SMTP password-file
or `_FILE` reader. Do not add an ineffective Compose secret mount. `community.sops`
decrypts on the controller; native Ansible API requests use `no_log`. Omada persists
SMTP settings in its sensitive controller data, covered by the existing protected
backup/recovery scope. SOPS remains desired authority, not another plaintext copy
in Compose's interpolation environment.

The pinned OpenTofu provider models notification toggles, but not SMTP or recipients.
Keep adoption separate and require import-only no-op plans before behavior changes.

## Interface and primary sources

The native role is version-bound to the reviewed `6.3.0.45` interface: SMTP
`GET/PATCH /{controller}/api/v2/global/settings/mail-server`, read-only site
notification `GET /{controller}/api/v2/sites/{site}/logs/notification`, and opt-in test mail
`POST /{controller}/api/v2/settings/test-mail`. The bundled native UI supplies the
SMTP form fields and masked-password test behavior. Requalify after upgrades.

- [Proton SMTP submission and dedicated tokens](https://proton.me/support/smtp-submission).
- [TP-Link SMTP encryption, including STARTTLS](https://www.tp-link.com/us/support/faq/3260/).
- [Image configuration interfaces](https://github.com/mbentley/docker-omada-controller#optional-environment-variables).
- [Pinned provider notification coverage](https://github.com/wncservices/terraform-provider-omada/blob/v0.13.0/docs/resources/notification_settings.md).
- [Provider's whole-document notification writer](https://github.com/wncservices/terraform-provider-omada/blob/v0.13.0/internal/omada/notification.go).
