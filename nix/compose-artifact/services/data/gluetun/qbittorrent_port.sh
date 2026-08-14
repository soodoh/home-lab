#!/bin/sh

echo "Executing port forwarding script..."

QBITTORRENT_BASE_URL=http://127.0.0.1:8081
FORWARDED_PORT=$(cat /tmp/gluetun/forwarded_port 2>/dev/null)
LOG_PREFIX="[qbittorrent]"

# Early exit conditions
if [ -z "$FORWARDED_PORT" ]; then
  echo "$LOG_PREFIX Current port has not yet been set!"
  exit 0
fi

# Wait for the service to be available
while ! wget -O - "${QBITTORRENT_BASE_URL}/api/v2/app/version" >/dev/null 2>&1; do
  echo "$LOG_PREFIX Waiting qBittorrent to be available..."
  sleep 10
done

echo "$LOG_PREFIX Updating qBittorrent's Listening Port..."

wget --method=POST \
  --header="Content-Type: application/x-www-form-urlencoded" \
  --body-data="json={\"listen_port\": $FORWARDED_PORT}" \
  --quiet \
  "${QBITTORRENT_BASE_URL}/api/v2/app/setPreferences"

# Check wget's exit status
if [ $? -eq 0 ]; then
  echo "$LOG_PREFIX Successfully updated qBittorrent's port to $FORWARDED_PORT"
else
  echo "$LOG_PREFIX Failed to update qBittorrent's port"
fi
