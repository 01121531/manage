#!/bin/sh
set -eu

password_file=${REDIS_HEALTHCHECK_PASSWORD_FILE:?REDIS_HEALTHCHECK_PASSWORD_FILE is required}
if ! exec 9<"$password_file"; then
  echo "Redis healthcheck credential file is not readable" >&2
  exit 1
fi
if [ ! -f "/proc/self/fd/9" ] || [ ! "$password_file" -ef "/proc/self/fd/9" ]; then
  exec 9<&-
  echo "Redis healthcheck credential file is invalid" >&2
  exit 1
fi
IFS= read -r password <&9 || true
extra=
if IFS= read -r extra <&9 || [ -n "$extra" ]; then
  exec 9<&-
  echo "Redis healthcheck credential file must contain one line" >&2
  exit 1
fi
if [ ! "$password_file" -ef "/proc/self/fd/9" ]; then
  exec 9<&-
  echo "Redis healthcheck credential file changed while being read" >&2
  exit 1
fi
exec 9<&-
if [ -z "$password" ]; then
  echo "Redis healthcheck credential file is empty" >&2
  exit 1
fi
printf '%s\n' "$password" | redis-cli --no-auth-warning --askpass --user healthcheck ping
