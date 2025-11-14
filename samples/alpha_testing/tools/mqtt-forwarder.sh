#!/usr/bin/env sh
#
# mqtt-forwarder.sh
# Subscribes to an MQTT topic and republishes all received messages to another topic.
#
# Usage:
#   ./mqtt-forwarder.sh [broker] [input_topic] [output_topic] [username] [password]
#
# Example:
#   ./mqtt-forwarder.sh localhost sensor/data sensor/processed
#

set -euo pipefail

BROKER="${1:-localhost}"
IN_TOPIC="${2:-twister/input}"
OUT_TOPIC="${3:-twister/output}"
USERNAME="${4:-}"
PASSWORD="${5:-}"

echo "Forwarding messages from '$IN_TOPIC' → '$OUT_TOPIC' via broker '$BROKER'..."
[[ -n "$USERNAME" ]] && AUTH_OPTS="-u $USERNAME"
[[ -n "$PASSWORD" ]] && AUTH_OPTS="$AUTH_OPTS -P $PASSWORD"

mosquitto_sub -h "$BROKER" -t "$IN_TOPIC" | while IFS= read -r msg; do
    if [[ -n "$msg" ]]; then
        mosquitto_pub -h "$BROKER" -t "$OUT_TOPIC" -m "$msg"
        echo "[$(date +'%H:%M:%S')] Forwarded: $msg"
    fi
done