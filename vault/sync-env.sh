#!/bin/bash

set -e

JSON_PAYLOAD="$1"

LOG_DIR="/vault/logs"
SERVER_LOG="$LOG_DIR/vault-server.log"


vault server -config=/vault/config/config.hcl >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

sleep 3
echo "Vault waiting..."

for i in {1..30}; do
  if vault status >/dev/null 2>&1; then
    echo "✓ Vault ready!"
    break
  fi
  sleep 1
done

INIT_OUTPUT=$(vault operator init -format=json -key-shares=1 -key-threshold=1)

UNSEAL_KEY=$(echo $INIT_OUTPUT | jq -r .unseal_keys_b64[0])
ROOT_TOKEN=$(echo $INIT_OUTPUT | jq -r .root_token)

echo "Unseal Key: $UNSEAL_KEY" > vault_keys.txt
echo "Root Token: $ROOT_TOKEN" >> vault_keys.txt

vault operator unseal $UNSEAL_KEY
vault login $ROOT_TOKEN > /dev/null

vault secrets enable -path=secret kv-v2 2>/dev/null || true

vault audit enable file \
  file_path="/vault/logs/vault-audit.log" \
  hmac_accessor=false \
  elide_list_responses=true

if [ -n "$JSON_PAYLOAD" ] && [ "$JSON_PAYLOAD" != "{}" ]; then
  echo "$JSON_PAYLOAD" | vault kv put secret/env -
else
    echo "❌ No environment variables to sync."
    exit 1
fi

vault policy write backend-policy - <<EOF
path "secret/data/env" {
  capabilities = ["read"]
}
EOF

BACKEND_TOKEN=$(vault token create -policy=backend-policy -format=json | jq -r .auth.client_token)

echo "========================================="
echo "Backend Token: $BACKEND_TOKEN"
echo "========================================="

wait $SERVER_PID