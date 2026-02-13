#!/usr/bin/env bash
set -euo pipefail

# deploy-bosh-dev.sh
# Clone bosh-deployment, create/upload a dev release for uaa-lite, and deploy a director

usage() {
  cat <<EOF
Usage: $0 [options]

Environment variables used:
  BOSH_ENVIRONMENT, BOSH_CLIENT, BOSH_CLIENT_SECRET, BOSH_CA_CERT - must be set to target an existing director
  DEPLOYMENT_NAME - optional (default: bosh)
  INTERNAL_IP - optional (default: 10.244.0.2)
  VARS_STORE - optional (default: creds.yml)
  SKIP_CONFIG_SERVER - optional (default: false) - set to true to skip config-server deployment

This script will:
  - Clone https://github.com/cloudfoundry/bosh-deployment into a temp dir
  - Create and upload a dev release from the repository root
  - Deploy the bosh director using bosh-deployment + operations/uaa-lite.yml + misc/bosh-dev.yml
  - Deploy config-server with director as a client (unless SKIP_CONFIG_SERVER=true)
EOF
}

if [[ "${1:-}" =~ ^(-h|--help)$ ]]; then
  usage
  exit 0
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEMP_DIR=$(mktemp -d)
BOSH_DEPLOYMENT_REPO="https://github.com/cloudfoundry/bosh-deployment.git"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-bosh}"
INTERNAL_IP="${INTERNAL_IP:-10.244.0.2}"
VARS_STORE="${VARS_STORE:-creds.yml}"
SKIP_CONFIG_SERVER="${SKIP_CONFIG_SERVER:-false}"

cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "Cloning bosh-deployment into $TEMP_DIR"
git clone --depth 1 "$BOSH_DEPLOYMENT_REPO" "$TEMP_DIR/bosh-deployment"

echo "Creating and uploading dev release from $ROOT_DIR"
# Create and upload dev release (force to overwrite existing dev release)
cd "$ROOT_DIR"
if ! bosh --version >/dev/null 2>&1; then
  echo "Error: bosh CLI not found in PATH"
  exit 1
fi

bosh create-release --dir . --force
bosh upload-release --dir .

echo "Deploying director using bosh-deployment and operations/uaa-lite.yml"
BOSH_CMD=(bosh -n deploy "$TEMP_DIR/bosh-deployment/bosh.yml" -d "$DEPLOYMENT_NAME")
BOSH_CMD+=( -o "$TEMP_DIR/bosh-deployment/bosh-lite.yml" )
BOSH_CMD+=( -o "$ROOT_DIR/operations/uaa-lite.yml" )
BOSH_CMD+=( -o "$ROOT_DIR/operations/set-instance-type-medium.yml" )
BOSH_CMD+=( -o "$TEMP_DIR/bosh-deployment/misc/bosh-dev.yml" )
if [ "$SKIP_CONFIG_SERVER" != "true" ]; then
  echo "Including config-server in deployment"
  BOSH_CMD+=( -o "$TEMP_DIR/bosh-deployment/misc/config-server.yml" )
fi
BOSH_CMD+=( -v internal_ip="$INTERNAL_IP" )
BOSH_CMD+=( -v director_name="${DEPLOYMENT_NAME}-dev" )
BOSH_CMD+=( --vars-store="$VARS_STORE" )

# Run bosh deploy
"${BOSH_CMD[@]}"

echo "Deployment finished. Vars stored in $VARS_STORE"

echo "To target the deployed director run:"
echo "  bosh alias-env ${DEPLOYMENT_NAME} -e ${INTERNAL_IP} --ca-cert <(bosh int $VARS_STORE --path /director_ssl/ca)"
echo "  bosh -e ${DEPLOYMENT_NAME} login"

exit 0
