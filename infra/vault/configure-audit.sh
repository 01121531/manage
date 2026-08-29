#!/bin/sh
set -eu

: "${VAULT_ADDR:?set VAULT_ADDR for the target Vault}"
case "$VAULT_ADDR" in
  https://*) ;;
  *)
    echo "VAULT_ADDR must use HTTPS" >&2
    exit 1
    ;;
esac

command -v vault >/dev/null 2>&1 || {
  echo "vault CLI is required" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "jq is required" >&2
  exit 1
}

primary_device=email-platform-primary
secondary_device=email-platform-secondary
primary_file=/var/log/vault-audit/email-platform-primary.json
secondary_file=/var/lib/vault-audit/email-platform-secondary.json

refresh_devices() {
  audit_devices_json=$(vault audit list -format=json)
  if ! printf '%s' "$audit_devices_json" | jq -e 'type == "object"' >/dev/null; then
    echo "Vault returned an invalid audit device list" >&2
    exit 1
  fi
}

device_exists() {
  printf '%s' "$audit_devices_json" |
    jq -e --arg key "$1" 'has($key)' >/dev/null
}

device_matches() {
  printf '%s' "$audit_devices_json" |
    jq -e --arg key "$1" --arg file_path "$2" '
      .[$key] as $device
      | ($device | type) == "object"
        and $device.type == "file"
        and $device.options.file_path == $file_path
        and $device.options.mode == "0600"
        and $device.options.format == "json"
        and $device.options.log_raw == "false"
        and $device.options.hmac_accessor == "true"
        and $device.options.elide_list_responses == "true"
    ' >/dev/null
}

ensure_device() {
  target_device=$1
  target_file=$2
  target_key="${target_device}/"

  if device_exists "$target_key"; then
    if ! device_matches "$target_key" "$target_file"; then
      echo "Existing audit device $target_device differs from reviewed configuration" >&2
      exit 1
    fi
    return
  fi

  vault audit enable -path="$target_device" file \
    file_path="$target_file" \
    mode=0600 \
    format=json \
    log_raw=false \
    hmac_accessor=true \
    elide_list_responses=true

  refresh_devices
  if ! device_matches "$target_key" "$target_file"; then
    echo "Audit device $target_device was not enabled with reviewed configuration" >&2
    exit 1
  fi
}

refresh_devices
ensure_device "$primary_device" "$primary_file"
ensure_device "$secondary_device" "$secondary_file"

refresh_devices
if ! device_matches "$primary_device/" "$primary_file" ||
  ! device_matches "$secondary_device/" "$secondary_file"; then
  echo "Final audit device verification failed" >&2
  exit 1
fi

echo "Two persistent Vault audit devices match reviewed configuration; credentials were not inspected or printed."
