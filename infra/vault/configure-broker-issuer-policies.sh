#!/bin/sh
set -eu

# This helper installs only the three reviewed broker issuer policies. It never
# binds a broker identity or reads, creates, exchanges, prints, or stores any
# RoleID, SecretID, token, or accessor.
: "${VAULT_ADDR:?set VAULT_ADDR for the target Vault}"
case "$VAULT_ADDR" in
  https://*) ;;
  *)
    echo "Vault broker issuer policy preflight failed" >&2
    exit 1
    ;;
esac

for tool in vault jq cmp mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Vault broker issuer policy preflight failed" >&2
    exit 1
  }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary_dir=$(mktemp -d) || {
  echo "Vault broker issuer policy preflight failed" >&2
  exit 1
}
trap 'rm -rf -- "$temporary_dir"' EXIT HUP INT TERM

policy_failed() {
  echo "Vault broker issuer policy configuration failed" >&2
  exit 1
}

configure_policy() {
  policy_name=$1
  policy_file=$2
  local_copy="$temporary_dir/$policy_name.local.hcl"
  remote_copy="$temporary_dir/$policy_name.remote.hcl"

  cp "$policy_file" "$local_copy" >/dev/null 2>&1 || policy_failed
  vault policy write "$policy_name" "$policy_file" >/dev/null 2>&1 ||
    policy_failed
  policy_json=$(vault read -format=json "sys/policies/acl/$policy_name" 2>/dev/null) ||
    policy_failed
  printf '%s' "$policy_json" | jq -ej '.data.policy' >"$remote_copy" 2>/dev/null ||
    policy_failed
  vault policy fmt "$local_copy" >/dev/null 2>&1 || policy_failed
  vault policy fmt "$remote_copy" >/dev/null 2>&1 || policy_failed
  cmp -s "$local_copy" "$remote_copy" || policy_failed
}

configure_policy \
  email-platform-broker-issuer-api \
  "$script_dir/policies/email-platform-broker-issuer-api.hcl"
configure_policy \
  email-platform-broker-issuer-mail \
  "$script_dir/policies/email-platform-broker-issuer-mail.hcl"
configure_policy \
  email-platform-broker-issuer-sub2 \
  "$script_dir/policies/email-platform-broker-issuer-sub2.hcl"

echo "Vault broker issuer policies match reviewed configuration; no credentials or identity bindings were read or changed."
