#!/bin/sh
set -eu

# Runs only for a new PostgreSQL volume.  The bootstrap/migration owner creates
# separate platform and Keycloak logins. Read each password from its mounted
# file and export it only for psql's \getenv; no password enters argv or output.
read_secret_file() {
  variable_name=$1
  file_path=$2
  if ! exec 9<"$file_path"; then
    echo "$variable_name file is not readable" >&2
    exit 1
  fi
  if [ ! -f "/proc/self/fd/9" ] || [ ! "$file_path" -ef "/proc/self/fd/9" ]; then
    exec 9<&-
    echo "$variable_name file is invalid" >&2
    exit 1
  fi
  IFS= read -r value <&9 || true
  extra=
  if IFS= read -r extra <&9 || [ -n "$extra" ]; then
    exec 9<&-
    echo "$variable_name file must contain one line" >&2
    exit 1
  fi
  if [ ! "$file_path" -ef "/proc/self/fd/9" ]; then
    exec 9<&-
    echo "$variable_name file changed while being read" >&2
    exit 1
  fi
  exec 9<&-
  if [ -z "$value" ]; then
    echo "$variable_name file is empty" >&2
    exit 1
  fi
  export "$variable_name=$value"
}

read_secret_file POSTGRES_BOOTSTRAP_PASSWORD "$POSTGRES_PASSWORD_FILE"
read_secret_file POSTGRES_APP_PASSWORD "$POSTGRES_APP_PASSWORD_FILE"
read_secret_file KEYCLOAK_DB_PASSWORD "$KEYCLOAK_DB_PASSWORD_FILE"

if [ "$KEYCLOAK_DB_USER" = "$POSTGRES_USER" ] || [ "$KEYCLOAK_DB_USER" = "$POSTGRES_APP_USER" ]; then
  echo "Keycloak database role must be distinct from PostgreSQL platform roles" >&2
  exit 1
fi
if [ "$KEYCLOAK_DB_PASSWORD" = "$POSTGRES_BOOTSTRAP_PASSWORD" ] || [ "$KEYCLOAK_DB_PASSWORD" = "$POSTGRES_APP_PASSWORD" ]; then
  echo "Keycloak database password must be distinct from PostgreSQL platform passwords" >&2
  exit 1
fi

psql \
  --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_user POSTGRES_APP_USER
\getenv app_password POSTGRES_APP_PASSWORD
\getenv keycloak_user KEYCLOAK_DB_USER
\getenv keycloak_password KEYCLOAK_DB_PASSWORD

SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT',
  :'app_user',
  :'app_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user') \gexec

SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT',
  :'keycloak_user',
  :'keycloak_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'keycloak_user') \gexec

SELECT format('ALTER DATABASE keycloak OWNER TO %I', :'keycloak_user') \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'app_user') \gexec
GRANT USAGE ON SCHEMA public TO :"app_user";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"app_user";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO :"app_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";
SQL

unset POSTGRES_BOOTSTRAP_PASSWORD POSTGRES_APP_PASSWORD KEYCLOAK_DB_PASSWORD

# Existing volumes may already contain Keycloak objects owned by the old
# bootstrap role. Re-running this script during the documented upgrade moves
# only objects in the Keycloak database to the dedicated runtime owner.
psql \
  --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname keycloak <<'SQL'
\getenv bootstrap_user POSTGRES_USER
\getenv keycloak_user KEYCLOAK_DB_USER
REASSIGN OWNED BY :"bootstrap_user" TO :"keycloak_user";
SQL
