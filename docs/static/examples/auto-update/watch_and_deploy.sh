#!/usr/bin/env bash
set -euo pipefail

default_images() {
    docker compose config --images 2>/dev/null \
        | grep -E '^ghcr\.io/gosuda/portal:' \
        | sort -u \
        | tr '\n' ' ' || true
}

IMAGES="${IMAGES:-$(default_images)}"
IMAGES="${IMAGES:-ghcr.io/gosuda/portal:2}"
DIGEST_FILE="${DIGEST_FILE:-.portal_image_digest}"
INTERVAL="${INTERVAL:-60}"
SERVICES="${SERVICES:-portal}"

get_remote_digest() {
    for image in $IMAGES; do
        digest="$(docker manifest inspect "$image" 2>/dev/null \
            | grep -m1 '"digest"' \
            | awk -F'"' '{print $4}')"
        if [[ -z "$digest" ]]; then
            return 1
        fi
        printf '%s=%s\n' "$image" "$digest"
    done
}

echo "Watching $IMAGES for digest changes (interval: ${INTERVAL}s)"
echo "Compose services: $SERVICES"

update_services() {
    docker compose pull $SERVICES
    docker compose up -d --force-recreate --remove-orphans $SERVICES
}

while true; do
    if ! NEW_DIGEST=$(get_remote_digest); then
        NEW_DIGEST=""
    fi

    if [[ -z "$NEW_DIGEST" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Failed to fetch digest, retrying in ${INTERVAL}s"
        sleep "$INTERVAL"
        continue
    fi

    OLD_DIGEST=""
    if [[ -f "$DIGEST_FILE" ]]; then
        OLD_DIGEST=$(cat "$DIGEST_FILE")
    fi

    if [[ "$NEW_DIGEST" != "$OLD_DIGEST" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Digest changed: ${OLD_DIGEST:-<none>} -> $NEW_DIGEST"
        update_services
        echo "$NEW_DIGEST" > "$DIGEST_FILE"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Update completed"
    fi

    sleep "$INTERVAL"
done
