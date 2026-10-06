#!/bin/sh

umask 077
export LC_ALL=C

LOG_PREFIX="[MAM]"
MAM_URL="https://t.myanonamouse.net/json/dynamicSeedbox.php"
CURRENT_IP=$(cat /tmp/gluetun/ip 2>/dev/null)
RESPONSE_FILE=/tmp/MAM.output
# MAM documents/reports a 60-minute cooldown for seedbox IP changes.
# Use a small buffer before retrying.
COOLDOWN_RETRY_MINS=${MAM_COOLDOWN_RETRY_MINS:-65}
MAX_COOLDOWN_RETRIES=${MAM_MAX_COOLDOWN_RETRIES:-3}
COOLDOWN_RETRY_LOCK_FILE=/tmp/MAM.cooldown-retry.flock
# Should persist between container restarts
COOKIE_FILE=/gluetun/MAM.cookies
# Stage on the persistent filesystem so cookie publication is atomic.
TEMP_COOKIE_FILE=/gluetun/.MAM.cookies.next
COMMIT_COOKIE_FILE=/gluetun/.MAM.cookies.commit
BOOTSTRAP_COOKIE_FILE=/tmp/MAM.bootstrap.cookies
MAM_ID_FILE=${MAM_ID_FILE:-/run/secrets/mam_initial_id}

MAM_RETRY_ATTEMPT=${MAM_RETRY_ATTEMPT:-0}

echo "$LOG_PREFIX Executing seedbox IP script..."

# Install curl, since running in Gluetun's default Alpine container
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found! Installing..."
  # Gluetun container uses Alpine linux, so apk is used here
  apk update
  apk add curl
fi

# Early exit conditions
if [ -z "$CURRENT_IP" ]; then
  echo "$LOG_PREFIX Current IP has not yet been set!"
  exit 1
fi

has_session_cookie() {
  # Netscape cookie jars can include #HttpOnly_ domain prefixes.
  awk -F '\t' '$6 == "mam_id" && length($7) > 0 { found = 1 } END { exit !found }' "$1" 2>/dev/null
}

make_request() {
  echo "$LOG_PREFIX Initiating request..."
  if ! curl -sS --connect-timeout 15 --max-time 60 \
    -b "$REQUEST_COOKIE_FILE" -c "$TEMP_COOKIE_FILE" "$MAM_URL" >"$RESPONSE_FILE"; then
    echo "$LOG_PREFIX Request failed before receiving a response from MAM"
    return 1
  fi
  # Response bodies and session cookies are private; log only classified outcomes.
}

use_bootstrap_cookie() {
  printf '# Netscape HTTP Cookie File\n.myanonamouse.net\tTRUE\t/\tTRUE\t0\tmam_id\t%s\n' \
    "$INITIAL_ID" >"$BOOTSTRAP_COOKIE_FILE" || return 1
  REQUEST_COOKIE_FILE=$BOOTSTRAP_COOKIE_FILE
}

is_last_change_too_recent() {
  grep 'Last change too recent' "$RESPONSE_FILE" >/dev/null 2>/dev/null
}

is_success() {
  grep '"Success":true' "$RESPONSE_FILE" >/dev/null 2>/dev/null
}

is_session_error() {
  grep -E 'No Session Cookie|Invalid session' "$RESPONSE_FILE" >/dev/null 2>/dev/null
}

schedule_cooldown_retry() {
  sleep_seconds=$1
  next_attempt=$((MAM_RETRY_ATTEMPT + 1))

  if [ "$next_attempt" -gt "$MAX_COOLDOWN_RETRIES" ]; then
    echo "$LOG_PREFIX MAM cooldown is still active after $MAM_RETRY_ATTEMPT retry attempt(s); leaving update for the next Gluetun port-forward event."
    return 0
  fi

  (
    # Kernel ownership survives for the worker's lifetime, not the file's.
    # A killed hook/container cannot leave a stale lock after its processes exit.
    exec 9>"$COOLDOWN_RETRY_LOCK_FILE" || exit 1
    if ! flock -n 9; then
      echo "$LOG_PREFIX A MAM cooldown retry is already scheduled; not scheduling another."
      exit 0
    fi

    echo "$LOG_PREFIX MAM cooldown active; scheduling retry attempt $next_attempt/$MAX_COOLDOWN_RETRIES in $sleep_seconds seconds."
    (
      # The sleeping worker must not retain the current request's lock.
      exec 8>&-
      sleep "$sleep_seconds" || exit 1
      # Release before re-entering so another cooldown can schedule its retry.
      flock -u 9
      exec 9>&-
      MAM_RETRY_ATTEMPT=$next_attempt /bin/sh "$0"
    ) &
  )
}

# Serialize hooks/retries sharing the cookie jar and staging paths.
exec 8>/tmp/MAM.request.flock || exit 1
if ! flock -n 8; then
  echo "$LOG_PREFIX Another MAM request is active; skipping this hook."
  exit 0
fi
trap 'rm -f "$TEMP_COOKIE_FILE" "$COMMIT_COOKIE_FILE" "$BOOTSTRAP_COOKIE_FILE" "$RESPONSE_FILE"' 0

if [ ! -r "$MAM_ID_FILE" ] || ! INITIAL_ID=$(cat "$MAM_ID_FILE"); then
  echo "$LOG_PREFIX Bootstrap credential file is unavailable; converge credentials from SOPS."
  exit 1
fi
case "$INITIAL_ID" in
  ''|*[![:graph:]]*|mam_id=*)
    echo "$LOG_PREFIX Bootstrap credential must be a nonempty raw session ID."
    exit 1
    ;;
esac

# Keep the bootstrap generation inside the protected jar, not a second state file.
# curl ignores this comment. A deliberate SOPS rotation resets the session once;
# unchanged bootstrap inputs never replace a healthy refreshed cookie.
BOOTSTRAP_DIGEST=$(printf '%s' "$INITIAL_ID" | sha256sum)
BOOTSTRAP_TAG="# MAM bootstrap: ${BOOTSTRAP_DIGEST%% *}"
REQUEST_COOKIE_FILE=$COOKIE_FILE
if ! has_session_cookie "$COOKIE_FILE" || ! grep -Fqx "$BOOTSTRAP_TAG" "$COOKIE_FILE"; then
  echo "$LOG_PREFIX Initializing session from the configured bootstrap credential."
  use_bootstrap_cookie || exit 1
fi

if ! make_request; then
  exit 1
fi

# Only an explicit session error admits one fallback. Never rebootstrap for
# transport failures, cooldowns or arbitrary endpoint errors.
if is_session_error && [ "$REQUEST_COOKIE_FILE" = "$COOKIE_FILE" ]; then
  echo "$LOG_PREFIX Session rejected; trying the bootstrap credential once."
  use_bootstrap_cookie || exit 1
  make_request || exit 1
fi

if is_last_change_too_recent; then
  schedule_cooldown_retry $((COOLDOWN_RETRY_MINS * 60))
  exit 0
fi

if ! is_success; then
  if is_session_error; then
    echo "$LOG_PREFIX Session is invalid; update the MAM ID in Servarr SOPS and converge both consumers."
  else
    echo "$LOG_PREFIX Request failed with an unexpected MAM response"
  fi
  exit 1
fi

if ! has_session_cookie "$TEMP_COOKIE_FILE"; then
  echo "$LOG_PREFIX Successful response did not retain a session cookie; preserving the existing jar."
  exit 1
fi
{
  printf '%s\n' "$BOOTSTRAP_TAG"
  cat "$TEMP_COOKIE_FILE"
} >"$COMMIT_COOKIE_FILE" && mv "$COMMIT_COOKIE_FILE" "$COOKIE_FILE" || exit 1
echo "$LOG_PREFIX Request was successful!"
exit 0
