#!/bin/sh
set -eu

certificate=/run/secrets/internal-tls/tls.crt
private_key=/run/secrets/internal-tls/tls.key

if [ ! -r "$certificate" ] || [ ! -s "$certificate" ]; then
    echo "Web TLS certificate is missing or unreadable" >&2
    exit 1
fi
if [ ! -r "$private_key" ] || [ ! -s "$private_key" ]; then
    echo "Web TLS private key is missing or unreadable" >&2
    exit 1
fi
if [ -w "$private_key" ]; then
    echo "Web TLS private key must be mounted read-only" >&2
    exit 1
fi
