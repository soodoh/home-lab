#!/bin/sh

LOG_PREFIX="[MAM]"
MAM_URL="https://t.myanonamouse.net/json/dynamicSeedbox.php"
CURRENT_IP=$(cat /tmp/gluetun/ip 2>/dev/null)
RESPONSE_FILE=/tmp/MAM.output
# MAM documents/reports a 60-minute cooldown for seedbox IP changes.
# Use a small buffer before retrying.
COOLDOWN_RETRY_MINS=${MAM_COOLDOWN_RETRY_MINS:-65}
MAX_COOLDOWN_RETRIES=${MAM_MAX_COOLDOWN_RETRIES:-3}
COOLDOWN_RETRY_LOCK_DIR=/tmp/MAM.cooldown-retry.lock
# Should persist between container restarts
COOKIE_FILE=/gluetun/MAM.cookies
TEMP_COOKIE_FILE=/tmp/MAM.cookies

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

make_request() {
  grep mam_id "$COOKIE_FILE" >/dev/null 2>/dev/null
  if [ $? -ne 0 ]; then
    echo "$LOG_PREFIX No cookie file found, please reinitialize with a new MAM_ID"
    exit 1
  fi

  echo "$LOG_PREFIX Initiating request..."
  if ! curl -sS -b "$COOKIE_FILE" -c "$TEMP_COOKIE_FILE" "$MAM_URL" >"$RESPONSE_FILE"; then
    echo "$LOG_PREFIX Request failed before receiving a response from MAM"
    return 1
  fi

  # Unlike curl, wget only saves cookies on successful HTTP requests
  # wget \
  #   --load-cookies="$COOKIE_FILE" \
  #   --save-cookies="$COOKIE_FILE" \
  #   --keep-session-cookies \
  #   -O "$RESPONSE_FILE" \
  #   "$MAM_URL"
  echo "$LOG_PREFIX Received response: $(cat "$RESPONSE_FILE")"
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

  if ! mkdir "$COOLDOWN_RETRY_LOCK_DIR" 2>/dev/null; then
    echo "$LOG_PREFIX A MAM cooldown retry is already scheduled; not scheduling another."
    return 0
  fi

  echo "$LOG_PREFIX MAM cooldown active; scheduling retry attempt $next_attempt/$MAX_COOLDOWN_RETRIES in $sleep_seconds seconds."
  (
    trap 'rmdir "$COOLDOWN_RETRY_LOCK_DIR" 2>/dev/null' EXIT INT TERM
    sleep "$sleep_seconds"
    rmdir "$COOLDOWN_RETRY_LOCK_DIR" 2>/dev/null
    trap - EXIT INT TERM
    MAM_RETRY_ATTEMPT=$next_attempt /bin/sh "$0"
  ) &
}

# On first run, we need to create a new MAM_ID from myanonamouse's Security section
# And execute via `docker exec -it gluetun ash` & `MAM_ID=... sh /scripts/update_mam_ip.sh`
if [ -n "$MAM_ID" ]; then
  echo "$LOG_PREFIX MAM_ID environment detected... Creating a new session with this."
  printf ".myanonamouse.net\tTRUE\t/\tTRUE\t0\tmam_id\t%s" "$MAM_ID" >"$COOKIE_FILE"
fi

if ! make_request; then
  exit 1
fi

if is_last_change_too_recent; then
  schedule_cooldown_retry $((COOLDOWN_RETRY_MINS * 60))
  exit 0
fi

if ! is_success; then
  if is_session_error; then
    echo "$LOG_PREFIX Session is invalid; please reinitialize the session with a new MAM_ID"
  else
    echo "$LOG_PREFIX Request failed with an unexpected MAM response"
  fi
  exit 1
fi

mv "$TEMP_COOKIE_FILE" "$COOKIE_FILE"
echo "$LOG_PREFIX Request was successful!"
exit 0
