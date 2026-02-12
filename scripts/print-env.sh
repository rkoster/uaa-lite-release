#!/usr/bin/env bash
set -euo pipefail

# Print environment variables to target the bosh director deployed by
# scripts/deploy-bosh-dev.sh. Intended for use like:
#   eval "$(scripts/print-env.sh)"

VARS_STORE="${VARS_STORE:-creds.yml}"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-bosh}"
INTERNAL_IP="${INTERNAL_IP:-10.244.0.2}"
BOSH_PORT="${BOSH_PORT:-25555}"

if ! command -v bosh >/dev/null 2>&1; then
  cat >&2 <<'ERR'
Error: bosh CLI not found in PATH. Install the bosh CLI to use this script.
ERR
  exit 1
fi

get_var() { bosh int "$VARS_STORE" --path "$1"; }

# Read values from the vars store
ADMIN_PASSWORD="$(get_var /admin_password)"
# Extract director CA using `bosh int --path` for certificates
DIRECTOR_CA_RAW=""
if bosh int "$VARS_STORE" --path /director_ssl/ca >/dev/null 2>&1; then
  DIRECTOR_CA_RAW="$(bosh int "$VARS_STORE" --path /director_ssl/ca)"
fi

# Escape single quotes for safe single-quoted output
escape_single_quotes() {
  sed "s/'/'\"'\"'/g"
}

if [ -n "$ADMIN_PASSWORD" ]; then
  ADMIN_PASSWORD_ESCAPED="$(printf '%s' "$ADMIN_PASSWORD" | escape_single_quotes)"
fi

if [ -n "$DIRECTOR_CA_RAW" ]; then
  DIRECTOR_CA_ESCAPED="$(printf '%s' "$DIRECTOR_CA_RAW" | escape_single_quotes)"
fi

BOSH_ENVIRONMENT="https://${INTERNAL_IP}:${BOSH_PORT}"

# Print exports
printf 'export BOSH_CLIENT=admin\n'
if [ -n "${ADMIN_PASSWORD_ESCAPED:-}" ]; then
  printf "export BOSH_CLIENT_SECRET='%s'\n" "$ADMIN_PASSWORD_ESCAPED"
else
  printf 'export BOSH_CLIENT_SECRET=\n'
fi
printf 'export BOSH_ENVIRONMENT=%s\n' "$BOSH_ENVIRONMENT"
if [ -n "${DIRECTOR_CA_ESCAPED:-}" ]; then
  printf "export BOSH_CA_CERT='%s'\n" "$DIRECTOR_CA_ESCAPED"
fi
