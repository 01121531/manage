#!/bin/sh
set -eu

# This helper configures policies and AppRoles only. It reads back role metadata
# but never creates, reads, prints, or stores RoleIDs, SecretIDs, or tokens.
: "${VAULT_ADDR:?set VAULT_ADDR for the target Vault}"
case "$VAULT_ADDR" in
  https://*) ;;
  *)
    echo "Vault AppRole configuration preflight failed" >&2
    exit 1
    ;;
esac

command -v vault >/dev/null 2>&1 || {
  echo "Vault AppRole configuration preflight failed" >&2
  exit 1
}
command -v jq >/dev/null 2>&1 || {
  echo "Vault AppRole configuration preflight failed" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

configuration_failed() {
  echo "Vault AppRole configuration failed" >&2
  exit 1
}

verification_failed() {
  echo "Vault AppRole configuration verification failed" >&2
  exit 1
}

configure_role() {
  role_name=$1
  policy_name=$2
  policy_file=$3

  vault policy write "$policy_name" "$policy_file" >/dev/null 2>&1 ||
    configuration_failed
  vault write "auth/approle/role/$role_name" \
    bind_secret_id=true \
    token_policies="$policy_name" \
    token_no_default_policy=true \
    token_num_uses=0 \
    token_type=service \
    secret_id_ttl=10m \
    secret_id_num_uses=1 \
    token_ttl=15m \
    token_max_ttl=1h \
    token_explicit_max_ttl=1h \
    token_period=0 >/dev/null 2>&1 || configuration_failed

  role_json=$(vault read -format=json "auth/approle/role/$role_name" 2>/dev/null) ||
    verification_failed
  if ! printf '%s' "$role_json" | jq -e --arg policy "$policy_name" '
    .data as $role
    | ($role.bind_secret_id == true)
      and ($role.local_secret_ids == false)
      and ($role.secret_id_num_uses == 1)
      and ($role.secret_id_ttl == 600)
      and ($role.secret_id_bound_cidrs == [])
      and ($role.token_policies == [$policy])
      and ($role.token_no_default_policy == true)
      and ($role.token_type == "service")
      and ($role.token_ttl == 900)
      and ($role.token_max_ttl == 3600)
      and ($role.token_explicit_max_ttl == 3600)
      and ($role.token_period == 0)
      and ($role.token_num_uses == 0)
      and ($role.token_bound_cidrs == [])
      and (($role.alias_metadata // {}) == {})
  ' >/dev/null 2>&1; then
    verification_failed
  fi
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

echo "Vault policies and AppRoles match reviewed configuration; no credentials were generated or read."
