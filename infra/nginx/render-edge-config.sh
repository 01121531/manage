#!/bin/sh
set -eu

template=/etc/nginx/edge-template.conf
output=/etc/nginx/conf.d/email-platform.conf
certificate=/etc/nginx/tls/fullchain.pem
private_key=/etc/nginx/tls/privkey.pem

case "${PLATFORM_DOMAIN:-}" in
    ""|.*|*.|*..*|*[!A-Za-z0-9.-]*)
        echo "PLATFORM_DOMAIN must be a valid DNS name" >&2
        exit 1
        ;;
    *.*) ;;
    *)
        echo "PLATFORM_DOMAIN must contain a DNS suffix" >&2
        exit 1
        ;;
esac

if [ ! -r "$certificate" ] || [ ! -s "$certificate" ]; then
    echo "TLS certificate is missing or unreadable" >&2
    exit 1
fi
if [ ! -r "$private_key" ] || [ ! -s "$private_key" ]; then
    echo "TLS private key is missing or unreadable" >&2
    exit 1
fi

umask 077
sed "s/\${PLATFORM_DOMAIN}/${PLATFORM_DOMAIN}/g" "$template" > "$output"
if grep -q '\${PLATFORM_DOMAIN}' "$output"; then
    echo "Nginx domain rendering did not complete" >&2
    exit 1
fi

nginx -t -q
exec "$@"
