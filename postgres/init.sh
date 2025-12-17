#!/bin/bash
set -e

echo "Waiting for Vault to be ready and token to be available..."

# Token dosyasını bekle (vault init tamamlanana kadar)
TOKEN_FILE="/vault/tokens/backend_token.txt"
for i in {1..60}; do
  if [ -f "$TOKEN_FILE" ]; then
    echo "✓ Backend token found!"
    break
  fi
  echo "Waiting for Vault backend token... ($i/60)"
  sleep 2
done

if [ ! -f "$TOKEN_FILE" ]; then
  echo "❌ Backend token not found after 120 seconds"
  exit 1
fi

echo "Fetching database credentials from Vault..."

# Token'ı oku
VAULT_TOKEN=$(cat "$TOKEN_FILE")
VAULT_ADDR=${VAULT_ADDR:-"http://vault:8200"}

# Database bilgilerini Vault'tan al
RESPONSE=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  ${VAULT_ADDR}/v1/secret/data/env)

# JSON'dan bilgileri çıkar
export POSTGRES_USER=$(echo $RESPONSE | jq -r '.data.data.POSTGRES_USER // "postgres"')
export POSTGRES_PASSWORD=$(echo $RESPONSE | jq -r '.data.data.POSTGRES_PASSWORD // "postgres"')
export POSTGRES_DB=$(echo $RESPONSE | jq -r '.data.data.POSTGRES_DB // "pickle"')

echo "Database configuration loaded from Vault:"
echo "  User: $POSTGRES_USER"
echo "  Database: $POSTGRES_DB"

# PostgreSQL'i başlat
exec docker-entrypoint.sh postgres
