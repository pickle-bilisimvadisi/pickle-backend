#!/bin/sh

set -e

echo "🔄 Waiting for Vault to be ready..."

# Wait for Vault to be available
VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
max_attempts=60
attempt=0

while [ $attempt -lt $max_attempts ]; do
  if wget -q --spider "$VAULT_ADDR/v1/sys/health" 2>/dev/null; then
    echo "✓ Vault is ready!"
    break
  fi
  attempt=$((attempt + 1))
  echo "Waiting for Vault... ($attempt/$max_attempts)"
  sleep 2
done

if [ $attempt -eq $max_attempts ]; then
  echo "❌ Vault is not available after $max_attempts attempts"
  exit 1
fi

# Wait for backend token to be created by Vault
TOKEN_FILE="/vault/tokens/backend_token.txt"
echo "🔄 Waiting for backend token..."

attempt=0
while [ $attempt -lt $max_attempts ]; do
  if [ -f "$TOKEN_FILE" ]; then
    echo "✓ Backend token found!"
    break
  fi
  attempt=$((attempt + 1))
  echo "Waiting for backend token... ($attempt/$max_attempts)"
  sleep 2
done

if [ $attempt -eq $max_attempts ]; then
  echo "❌ Backend token not found after $max_attempts attempts"
  exit 1
fi

# Read the token
VAULT_TOKEN=$(cat "$TOKEN_FILE")
export VAULT_TOKEN

echo "🔄 Fetching environment variables from Vault..."

# Fetch environment variables from Vault
ENV_DATA=$(wget -qO- \
  --header "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/secret/data/env" 2>/dev/null || echo "")

if [ -z "$ENV_DATA" ]; then
  echo "❌ Failed to fetch environment variables from Vault"
  exit 1
fi

# Parse JSON and set environment variables directly
eval "$(echo "$ENV_DATA" | jq -r '.data.data | to_entries | .[] | "export \(.key)=\"\(.value)\""')"

echo "✅ Environment variables loaded from Vault"

# Override DATABASE_URL to use Docker service name instead of localhost
if [ -n "$DATABASE_URL" ]; then
  export DATABASE_URL=$(echo "$DATABASE_URL" | sed 's/@localhost:/@database:/g')
  echo "✅ Database URL updated: $DATABASE_URL"
fi

# Wait for database to be ready
echo "🔄 Waiting for database to be ready..."
max_db_attempts=60
db_attempt=0

while [ $db_attempt -lt $max_db_attempts ]; do
  if nc -z database 5432 2>/dev/null; then
    echo "✓ Database port is open!"
    # Give PostgreSQL extra time to fully initialize
    sleep 5
    echo "✓ Database should be ready now"
    break
  fi
  db_attempt=$((db_attempt + 1))
  echo "Waiting for database... ($db_attempt/$max_db_attempts)"
  sleep 2
done

if [ $db_attempt -eq $max_db_attempts ]; then
  echo "❌ Database is not ready after $max_db_attempts attempts"
  exit 1
fi

echo "🚀 Starting application..."

# Run Prisma migrations with retry
echo "🔄 Running Prisma migrations..."
max_migrate_attempts=5
migrate_attempt=0

while [ $migrate_attempt -lt $max_migrate_attempts ]; do
  if npx prisma migrate deploy; then
    echo "✅ Migrations completed successfully"
    break
  fi
  migrate_attempt=$((migrate_attempt + 1))
  if [ $migrate_attempt -lt $max_migrate_attempts ]; then
    echo "⚠️ Migration failed, retrying... ($migrate_attempt/$max_migrate_attempts)"
    sleep 5
  else
    echo "❌ Migrations failed after $max_migrate_attempts attempts"
    exit 1
  fi
done

# Start the application
exec node dist/main.js