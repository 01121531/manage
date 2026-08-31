#!/bin/sh
set -eu

# Configure only the reviewed secure-pool-import policies, AppRoles, and
# signing keys. This helper never creates, reads, prints, or stores RoleIDs,
# SecretIDs, tokens, token accessors, private keys, signatures, or pool data.
: "${VAULT_ADDR:?set VAULT_ADDR for the target Vault}"
case "$VAULT_ADDR" in
  https://*) ;;
  *)
    echo "Vault secure import configuration preflight failed" >&2
    exit 1
    ;;
esac

for tool in vault jq cmp mktemp cp; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Vault secure import configuration preflight failed" >&2
    exit 1
  }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
temporary_dir=$(mktemp -d) || {
  echo "Vault secure import configuration preflight failed" >&2
  exit 1
}
trap 'rm -rf -- "$temporary_dir"' EXIT HUP INT TERM

configuration_failed() {
  echo "Vault secure import configuration failed" >&2
  exit 1
}

verification_failed() {
  echo "Vault secure import configuration verification failed" >&2
  exit 1
}

configure_policy() {
  policy_name=$1
  policy_file=$2
  local_copy="$temporary_dir/$policy_name.local.hcl"
  remote_copy="$temporary_dir/$policy_name.remote.hcl"

  cp "$policy_file" "$local_copy" >/dev/null 2>&1 || configuration_failed
  vault policy write "$policy_name" "$policy_file" >/dev/null 2>&1 ||
    configuration_failed
  policy_json=$(vault read -format=json "sys/policies/acl/$policy_name" 2>/dev/null) ||
    verification_failed
  printf '%s' "$policy_json" | jq -ej '.data.policy' >"$remote_copy" 2>/dev/null ||
    verification_failed
  vault policy fmt "$local_copy" >/dev/null 2>&1 || verification_failed
  vault policy fmt "$remote_copy" >/dev/null 2>&1 || verification_failed
  cmp -s "$local_copy" "$remote_copy" || verification_failed
}

configure_role() {
  role_name=$1
  policy_name=$2

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

configure_key() {
  key_name=$1

  vault write "transit/keys/$key_name" \
    type=ed25519 \
    derived=false \
    exportable=false \
    allow_plaintext_backup=false \
    auto_rotate_period=720h >/dev/null 2>&1 || configuration_failed

  key_json=$(vault read -format=json "transit/keys/$key_name" 2>/dev/null) ||
    verification_failed
  if ! printf '%s' "$key_json" | jq -e --arg name "$key_name" '
    .data as $key
    | ($key.name == $name)
      and ($key.type == "ed25519")
      and ($key.derived == false)
      and ($key.exportable == false)
      and ($key.allow_plaintext_backup == false)
      and ($key.deletion_allowed == false)
      and ($key.auto_rotate_period == 2592000)
      and ($key.supports_signing == true)
      and ($key.latest_version >= 1)
      and ($key.keys | type == "object")
  ' >/dev/null 2>&1; then
    verification_failed
  fi
}

configure_policy \
  email-platform-card-importer \
  "$script_dir/policies/email-platform-card-importer.hcl"
configure_policy \
  email-platform-mailbox-importer \
  "$script_dir/policies/email-platform-mailbox-importer.hcl"
configure_policy \
  email-platform-api-cards \
  "$script_dir/policies/email-platform-api-cards.hcl"

configure_role email-platform-card-importer email-platform-card-importer
configure_role email-platform-mailbox-importer email-platform-mailbox-importer
configure_role email-platform-api-cards email-platform-api-cards

configure_key email-platform-card-import-receipt
configure_key email-platform-mailbox-import-receipt

echo "Vault secure import policies, AppRoles, and non-exportable signing keys match reviewed configuration; no credentials were generated or read."
