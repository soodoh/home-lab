#!/bin/sh

QBITTORRENT_BASE_URL=http://127.0.0.1:8081
FORWARDED_PORT=$(cat /tmp/gluetun/forwarded_port 2>/dev/null)
LOG_PREFIX="[qbittorrent]"

fail() {
  echo "$LOG_PREFIX $1" >&2
  exit 1
}

# Refuse missing, malformed or out-of-range ports before constructing API JSON.
case "$FORWARDED_PORT" in
  ''|*[!0-9]*|0*) fail "The forwarded port is unavailable or invalid." ;;
esac
if [ "${#FORWARDED_PORT}" -gt 5 ] || [ "$FORWARDED_PORT" -gt 65535 ]; then
  fail "The forwarded port is out of range."
fi

# Gluetun becomes healthy before its namespace dependents start. Wait for
# qBittorrent, but do not leave a broken hook waiting indefinitely.
attempt=0
while ! wget --quiet --tries=1 --timeout=5 -O /dev/null \
  "${QBITTORRENT_BASE_URL}/api/v2/app/version" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 60 ] || fail "qBittorrent did not become available."
  echo "$LOG_PREFIX Waiting for qBittorrent to be available..."
  sleep 5
done

echo "$LOG_PREFIX Updating qBittorrent's Listening Port..."
if ! wget --method=POST --tries=1 --timeout=5 \
  --header="Content-Type: application/x-www-form-urlencoded" \
  --body-data="json={\"listen_port\": $FORWARDED_PORT}" \
  --quiet -O /dev/null \
  "${QBITTORRENT_BASE_URL}/api/v2/app/setPreferences"; then
  fail "Failed to update qBittorrent's port."
fi

# The API can accept a request without applying the expected setting. Read
# back only for validation; preferences may contain secrets and must not log.
if ! preferences=$(wget --quiet --tries=1 --timeout=5 -O - \
  "${QBITTORRENT_BASE_URL}/api/v2/app/preferences"); then
  fail "Failed to read back qBittorrent's port."
fi
if ! printf '%s\n' "$preferences" | grep -Eq \
  "\"listen_port\"[[:space:]]*:[[:space:]]*${FORWARDED_PORT}[[:space:]]*[,}]"; then
  fail "qBittorrent's listening port does not match the forwarded port."
fi
unset preferences

echo "$LOG_PREFIX Successfully verified qBittorrent's port as $FORWARDED_PORT"
