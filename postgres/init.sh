#!/bin/bash
set -e

echo "Waiting for Vault to be ready and token to be available..."

# 1. Token dosyasını bekle
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

# 2. Token ve Adres tanımları
VAULT_TOKEN=$(cat "$TOKEN_FILE")
VAULT_ADDR=${VAULT_ADDR:-"http://vault:8200"}

# 3. Vault'tan veriyi çek
RESPONSE=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  ${VAULT_ADDR}/v1/secret/data/env)

# 4. DATABASE_URL'i al (Eğer Vault'ta yoksa environment'taki yedeği kullanır)
# Örnek Link: postgresql://eyasa:10kals192csd14p@localhost:5432/pickledb?schema=public
FULL_DB_URL=$(echo $RESPONSE | jq -r '.data.data.DATABASE_URL // empty')

if [ -z "$FULL_DB_URL" ]; then
    echo "⚠️  DATABASE_URL not found in Vault, checking environment..."
    FULL_DB_URL="$DATABASE_URL"
fi

echo "Parsing DATABASE_URL configuration..."

# 5. URL'den bilgileri ayıkla (Regex/Sed kullanarak)
# Kullanıcı adı (:// ile : arasındaki kısım)
DB_USER=$(echo "$FULL_DB_URL" | sed -n 's|.*://\([^:]*\):.*|\1|p')

# Şifre (: ile @ arasındaki kısım)
DB_PASS=$(echo "$FULL_DB_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')

# Veritabanı adı (/ ile ? arasındaki kısım - ? yoksa sonuna kadar alır)
DB_NAME=$(echo "$FULL_DB_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

# Debug için çıktı (Şifreyi gizleyerek)
echo "Configuration extracted:"
echo "  User: $DB_USER"
echo "  DB:   $DB_NAME"
echo "  Pass: ****** (Set)"

# 6. PostgreSQL Environment Değişkenlerini Ayarla
if [ -n "$DB_PASS" ]; then
  export POSTGRES_USER="$DB_USER"
  export POSTGRES_PASSWORD="$DB_PASS"
  export POSTGRES_DB="$DB_NAME"
  
  # --- YENİ EKLENEN KISIM ---
  # Kullanıcı adını bir dosyaya yazıyoruz ki healthcheck bunu okuyabilsin
  echo "$DB_USER" > /tmp/pg_user
  echo "$DB_NAME" > /tmp/pg_db
  # --------------------------
  
else
  echo "❌ Error: Could not parse password from DATABASE_URL or it is empty."
  exit 1
fi

# 7. PostgreSQL'i başlat
exec docker-entrypoint.sh postgres