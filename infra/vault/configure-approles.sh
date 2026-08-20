#!/bin/sh
set -eu

# This helper configures policies and AppRoles only. It never creates, reads,
# prints, or stores RoleIDs, SecretIDs, or service tokens.
: "${VAULT_ADDR:?set VAULT_ADDR for the target Vault}"
command -v vault >/dev/null 2>&1 || {
  echo "vault CLI is required" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

configure_role() {
  role_name=$1
  policy_name=$2
  policy_file=$3

  vault policy write "$policy_name" "$policy_file"
  vault write "auth/approle/role/$role_name" \
    bind_secret_id=true \
    token_policies="$policy_name" \
    token_no_default_policy=true \
    token_type=service \
    secret_id_ttl=10m \
    secret_id_num_uses=1 \
    token_ttl=15m \
    token_max_ttl=1h
}

configure_role \
  email-platform-api-cards \
  email-platform-api-cards \
  "$script_dir/policies/email-platform-api-cards.hcl"
configure_role \
  email-platform-mail \
  email-platform-mail \
  "$script_dir/policies/email-platform-mail.hcl"
configure_role \
  email-platform-sub2 \
  email-platform-sub2 \
  "$script_dir/policies/email-platform-sub2.hcl"

echo "Vault policies and AppRoles configured; no credentials were generated."
