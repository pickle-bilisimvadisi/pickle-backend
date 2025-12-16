#!/bin/bash

set -e

ENV_FILE="/vault/.env"
VAULT_PATH="secret/env"

if [ ! -f "$ENV_FILE" ]; then
  echo "❌ .env file not found: $ENV_FILE"
  exit 1
fi

declare -A env_vars

while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
  
  value=$(echo "$value" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
  
  env_vars["$key"]="$value"
done < "$ENV_FILE"

json_data="{"
first=true
for key in "${!env_vars[@]}"; do
  if [ "$first" = true ]; then
    first=false
  else
    json_data+=","
  fi
  json_data+="\"$key\":\"${env_vars[$key]}\""
done
json_data+="}"

echo "📍 Path: $VAULT_PATH"
rm -rf $env
bash /vault/sync-env.sh "$json_data"