#!/bin/sh
set -eu

template=/etc/nginx/edge-template.conf
output=/etc/nginx/conf.d/email-platform.conf
certificate=/etc/nginx/tls/fullchain.pem
private_key=/etc/nginx/tls/privkey.pem
internal_ca=/run/secrets/internal-tls/ca.crt
active_slot=/etc/nginx/edge-routing/active-slot.conf

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
if [ -w "$private_key" ]; then
    echo "TLS private key must be mounted read-only" >&2
    exit 1
fi
if [ ! -r "$internal_ca" ] || [ ! -s "$internal_ca" ]; then
    echo "Internal TLS CA is missing or unreadable" >&2
    exit 1
fi
if [ ! -r "$active_slot" ] || [ ! -s "$active_slot" ]; then
    echo "Active edge slot configuration is missing or unreadable" >&2
    exit 1
fi
if ! cmp -s "$active_slot" /etc/nginx/edge-routing-templates/blue.conf \
    && ! cmp -s "$active_slot" /etc/nginx/edge-routing-templates/green.conf; then
    echo "Active edge slot configuration is not canonical" >&2
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
