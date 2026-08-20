#!/bin/sh

# Read-only helper for locating the system CA bundle used by Nginx.
for mail_helper_ca_path in \
    /etc/pki/tls/certs/ca-bundle.crt \
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/ssl/cert.pem
do
    if [ -f "$mail_helper_ca_path" ]; then
        printf '%s\n' "$mail_helper_ca_path"
        exit 0
    fi
done

printf '%s\n' "No system CA bundle was found. Install the ca-certificates package first." >&2
exit 1
