#!/bin/sh
set -eu

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_PASSWORD_FILE:?POSTGRES_PASSWORD_FILE is required}"
: "${POSTGRES_APP_USER:?POSTGRES_APP_USER is required}"
: "${POSTGRES_APP_PASSWORD_FILE:?POSTGRES_APP_PASSWORD_FILE is required}"
: "${KEYCLOAK_DB_USER:?KEYCLOAK_DB_USER is required}"
: "${KEYCLOAK_DB_PASSWORD_FILE:?KEYCLOAK_DB_PASSWORD_FILE is required}"

umask 077
pgpass_file=$(mktemp /tmp/postgres-healthcheck.XXXXXX)
trap 'rm -f "$pgpass_file"' EXIT
trap 'exit 1' HUP INT TERM
chmod 600 "$pgpass_file"

escape_pgpass_field() {
  sed -e 's/\\/\\\\/g' -e 's/:/\\:/g'
}

check_database() {
  database=$1
  username=$2
  password_file=$3

  if ! exec 9<"$password_file"; then
    echo "PostgreSQL healthcheck credential file is not readable" >&2
    return 1
  fi
  if [ ! -f "/proc/self/fd/9" ] || [ ! "$password_file" -ef "/proc/self/fd/9" ]; then
    exec 9<&-
    echo "PostgreSQL healthcheck credential file is invalid" >&2
    return 1
  fi
  IFS= read -r password <&9 || true
  extra=
  if IFS= read -r extra <&9 || [ -n "$extra" ]; then
    exec 9<&-
    echo "PostgreSQL healthcheck credential file must contain one line" >&2
    return 1
  fi
  if [ ! "$password_file" -ef "/proc/self/fd/9" ]; then
    exec 9<&-
    echo "PostgreSQL healthcheck credential file changed while being read" >&2
    return 1
  fi
  exec 9<&-
  if [ -z "$password" ]; then
    echo "PostgreSQL healthcheck credential file is empty" >&2
    return 1
  fi

  database_field=$(printf '%s' "$database" | escape_pgpass_field)
  username_field=$(printf '%s' "$username" | escape_pgpass_field)
  password_field=$(printf '%s' "$password" | escape_pgpass_field)
  printf '127.0.0.1:5432:%s:%s:%s\n' \
    "$database_field" "$username_field" "$password_field" >> "$pgpass_file"
  unset password password_field

  PGPASSFILE="$pgpass_file" psql \
    --host=127.0.0.1 \
    --port=5432 \
    --username="$username" \
    --dbname="$database" \
    --no-password \
    --set=ON_ERROR_STOP=1 \
    --tuples-only \
    --no-align \
    --command='SELECT 1' >/dev/null
}

check_database "$POSTGRES_DB" "$POSTGRES_USER" "$POSTGRES_PASSWORD_FILE"
check_database "$POSTGRES_DB" "$POSTGRES_APP_USER" "$POSTGRES_APP_PASSWORD_FILE"
check_database "keycloak" "$KEYCLOAK_DB_USER" "$KEYCLOAK_DB_PASSWORD_FILE"
