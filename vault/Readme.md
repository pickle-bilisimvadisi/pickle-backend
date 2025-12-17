# HashiCorp Vault Setup

Docker-based Vault konfigürasyonu. Environment variable'ları güvenli şekilde saklayan ve backend'e policy-based token ile erişim sağlayan bir yapıdır.

## 🚀 Teknolojiler

- **HashiCorp Vault 1.21** - Secret management
- **KV-v2 Secret Engine** - Key-value storage
- **File Backend** - Storage backend
- **Policy-Based Access Control** - Token authorization
- **Audit Logging** - Operasyon loglama
- **Docker** - Konteynerizasyon

## 🔒 Güvenlik Özellikleri

- **Policy-Based Tokens**: Backend sadece okuma yetkisi alır
- **Audit Logging**: Tüm operasyonlar loglanır
- **Sealed/Unsealed State**: Initialize sonrası unseal gerekir
- **KV-v2 Versioning**: Secret versiyonlama desteği
- **File-Based Storage**: Development için local storage

## 📋 Dosya Yapısı

### `config.hcl`
Vault sunucu konfigürasyonu.

**Ayarlar:**
```hcl
storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://0.0.0.0:8200"
ui = true
disable_mlock = true
```

**Özellikler:**
- **Storage**: File-based (development için)
- **Listener**: `0.0.0.0:8200` (TLS disabled)
- **UI**: Web UI aktif
- **Mlock**: Docker için disabled

---

### `Dockerfile`
Vault container image tanımı.

**Base Image:** `hashicorp/vault:1.21`

**Yüklenen Paketler:**
- `jq` - JSON parsing
- `bash` - Script execution
- `curl` - HTTP requests

**Kopyalanan Dosyalar:**
- `init.sh` - Container başlangıç scripti
- `sync-env.sh` - Vault init ve token oluşturma
- `config.hcl` - Vault konfigürasyonu

**Port:** `8200`

---

### `init.sh`
Container başladığında çalışan ana script.

**İşlem Akışı:**

1. `.env` dosyasını okur (`/vault/.env`)
2. Key-value çiftlerini parse eder
3. JSON formatına dönüştürür
4. `sync-env.sh` scriptini çağırır

**Input:** `.env` file  
**Output:** JSON payload → `sync-env.sh`

**Örnek `.env` → JSON dönüşümü:**
```bash
DATABASE_URL=postgresql://...
JWT_SECRET=secret123
```
↓
```json
{
  "DATABASE_URL": "postgresql://...",
  "JWT_SECRET": "secret123"
}
```

---

### `sync-env.sh`
Vault'u başlatır, initialize eder ve secret'ları yükler.

**İşlem Adımları:**

1. **Vault Server Başlatma**
   - Background'da Vault server başlar
   - Config: `/vault/config/config.hcl`
   - Log: `/vault/logs/vault-server.log`

2. **Health Check**
   - 30 saniye boyunca Vault'un hazır olmasını bekler
   - `vault status` komutuyla kontrol eder

3. **Initialize**
   - Vault'u initialize eder
   - Key shares: 1
   - Key threshold: 1
   - Output: `vault_keys.txt` (unseal key + root token)

4. **Unseal**
   - Unseal key ile Vault'u açar
   - Root token ile login olur

5. **Secret Engine Aktif Etme**
   - KV-v2 secret engine'i `secret/` path'inde aktif eder

6. **Audit Log Aktif Etme**
   - File-based audit log aktif eder
   - Path: `/vault/logs/vault-audit.log`
   - HMAC accessor: disabled (daha okunaklı loglar)

7. **Secret Yükleme**
   - JSON payload'ı `secret/env` path'ine yazar
   - Tüm environment variable'lar bu path'te saklanır

8. **Policy Oluşturma**
   - `backend-policy` oluşturur
   - Sadece `secret/data/env` okuma yetkisi verir

   ```hcl
   path "secret/data/env" {
     capabilities = ["read"]
   }
   ```

9. **Backend Token Oluşturma**
   - `backend-policy` ile token oluşturur
   - Token'ı `/vault/tokens/backend_token.txt`'ye kaydeder
   - Bu token backend tarafından kullanılır

**Output Dosyalar:**
- `vault_keys.txt` - Unseal key ve root token
- `tokens/backend_token.txt` - Backend için policy-based token

---

## 🔑 Token Tipleri

### Root Token
**Konum:** `vault_keys.txt`

**Yetkiler:** 
- Tüm path'lere tam erişim
- Policy oluşturma/silme
- Secret engine yönetimi
- Token oluşturma/iptal etme

**Kullanım:** 
- ⚠️ **Sadece development için**
- Production'da güvenli şekilde saklanmalı
- Manuel operasyonlar için

**Örnek:**
```bash
vault login <root_token>
vault kv get secret/env
vault token create -policy=custom-policy
```

---

### Backend Token
**Konum:** `tokens/backend_token.txt`

**Policy:**
```hcl
path "secret/data/env" {
  capabilities = ["read"]
}
```

**Yetkiler:**
- ✅ `secret/data/env` okuma
- ❌ Yazma yetkisi yok
- ❌ Diğer path'lere erişim yok
- ❌ Admin operasyonlar yok

**Kullanım:**
- Backend uygulaması tarafından kullanılır
- Environment variable'ları okur
- Minimum privilege principle

**Backend'de Kullanım:**
```typescript
const vaultToken = fs.readFileSync('/vault/tokens/backend_token.txt', 'utf-8');
const response = await fetch('http://vault:8200/v1/secret/data/env', {
  headers: { 'X-Vault-Token': vaultToken }
});
const secrets = response.json().data.data;
```

---

## 📍 Secret Path Yapısı

### `secret/env`
Tüm environment variable'lar bu path'te saklanır.

**Vault API Path:** `secret/data/env` (KV-v2 için `/data/` eklenir)

**Stored Data:**
```json
{
  "DATABASE_URL": "postgresql://user:pass@postgres:5432/db",
  "JWT_SECRET": "secret-key",
  "JWT_REFRESH_SECRET": "refresh-secret",
  "EMAIL_HOST": "smtp.gmail.com",
  "EMAIL_PORT": "587",
  "EMAIL_USER": "user@gmail.com",
  "EMAIL_PASSWORD": "app-password",
  "R2_ACCESS_KEY": "access-key",
  "R2_SECRET_ACCESS_KEY": "secret-key",
  "R2_ACCOUNT_ID": "account-id",
  "R2_BUCKET_NAME": "bucket",
  "R2_ENDPOINT": "https://endpoint.r2.cloudflarestorage.com",
  "R2_PUBLIC_BASE_URL": "https://domain.com"
}
```

**Backend Okuma:**
```bash
# CLI ile okuma (root token gerekli)
vault kv get secret/env

# API ile okuma (backend token ile)
GET http://vault:8200/v1/secret/data/env
Header: X-Vault-Token: <backend_token>
```

---

## 🔧 Konfigürasyon Detayları

### Storage Backend
**Tip:** File-based storage

**Path:** `/vault/file`

**Özellikler:**
- Development için uygundur
- Production'da Consul, etcd veya cloud storage önerilir
- Data persistence için volume mount gerekir

**Docker Volume:**
```yaml
volumes:
  - vault-data:/vault/file
```

---

### Listener
**Address:** `0.0.0.0:8200`

**TLS:** Disabled (development için)

**API Endpoint:** `http://vault:8200`

**UI:** `http://localhost:8200/ui`

**⚠️ Production için:**
- TLS aktif edilmeli
- Valid sertifika kullanılmalı
- TLS 1.2+ zorunlu

---

### Audit Log
**Path:** `/vault/logs/vault-audit.log`

**Format:** JSON

**Log Edilen Operasyonlar:**
- Secret read/write/delete
- Token create/revoke
- Policy changes
- Authentication attempts

**Örnek Log Entry:**
```json
{
  "time": "2025-12-17T10:00:00.000Z",
  "type": "response",
  "auth": {
    "token_type": "service",
    "policies": ["backend-policy"]
  },
  "request": {
    "operation": "read",
    "path": "secret/data/env"
  },
  "response": {
    "data": { "..." }
  }
}
```

---

## 🚀 Çalışma Akışı

### Container Başlatma

```bash
docker-compose up -d vault
```

**Sıralı İşlemler:**

1. ✅ Dockerfile build edilir
2. ✅ Container başlatılır
3. ✅ `init.sh` çalışır
4. ✅ `.env` dosyası parse edilir
5. ✅ JSON oluşturulur
6. ✅ `sync-env.sh` çağrılır
7. ✅ Vault server background'da başlar
8. ✅ Health check (30 saniye timeout)
9. ✅ Vault initialize edilir
10. ✅ Unseal key ve root token kaydedilir
11. ✅ Vault unseal edilir
12. ✅ Root token ile login
13. ✅ KV-v2 secret engine aktif
14. ✅ Audit log aktif
15. ✅ Secret'lar `secret/env`'e yazılır
16. ✅ Backend policy oluşturulur
17. ✅ Backend token oluşturulur ve kaydedilir
18. ✅ Token console'a ve dosyaya yazılır
19. ✅ Server background'da çalışmaya devam eder

**Log Çıktısı:**
```
Vault waiting...
✓ Vault ready!
Unseal Key: <key>
Root Token: <token>
=========================================
Backend Token: <token>
=========================================
✓ Backend token saved to /vault/tokens/backend_token.txt
```

---

### Backend Entegrasyonu

**Backend Container'da Token Okuma:**

```typescript
// src/config/vault.config.ts
import * as fs from 'fs';

export const getVaultToken = (): string => {
  const tokenPath = '/vault/tokens/backend_token.txt';
  
  if (!fs.existsSync(tokenPath)) {
    throw new Error('Vault token not found');
  }
  
  return fs.readFileSync(tokenPath, 'utf-8').trim();
};

export const getSecretsFromVault = async () => {
  const token = getVaultToken();
  
  const response = await fetch('http://vault:8200/v1/secret/data/env', {
    headers: {
      'X-Vault-Token': token
    }
  });
  
  if (!response.ok) {
    throw new Error('Failed to fetch secrets from Vault');
  }
  
  const data = await response.json();
  return data.data.data; // KV-v2 nested data
};
```

**Docker Compose Volume Mount:**
```yaml
services:
  backend:
    volumes:
      - vault-tokens:/vault/tokens:ro  # read-only
    depends_on:
      - vault

  vault:
    volumes:
      - vault-tokens:/vault/tokens
      - ./vault/.env:/vault/.env:ro

volumes:
  vault-tokens:
```

---

## 📊 Güvenlik Best Practices

### Development
✅ File-based storage kullanılabilir  
✅ TLS disabled olabilir  
✅ Root token saklanabilir  
✅ Single unseal key yeterli  

### Production
⚠️ **Zorunlu Değişiklikler:**

1. **TLS Aktif Etme**
   ```hcl
   listener "tcp" {
     tls_cert_file = "/vault/tls/cert.pem"
     tls_key_file  = "/vault/tls/key.pem"
   }
   ```

2. **External Storage**
   - Consul, etcd, DynamoDB, Cloud Storage
   - High availability için gerekli

3. **Auto-Unseal**
   - AWS KMS, Azure Key Vault, GCP KMS
   - Manuel unseal yerine otomatik

4. **Multiple Unseal Keys**
   ```bash
   vault operator init -key-shares=5 -key-threshold=3
   ```
   - Shamir's Secret Sharing
   - 5 key, 3'ü gerekli

5. **Audit Log Güvenliği**
   - Remote log shipping
   - SIEM entegrasyonu
   - Log retention policy

6. **Token TTL**
   ```bash
   vault token create -policy=backend-policy -ttl=24h
   ```
   - Token expiration
   - Periodic renewal

7. **Network Segmentation**
   - Vault'a sadece backend erişebilmeli
   - Firewall rules
   - Private network

---

## ⚠️ Mevcut Özellikler

✅ **Var:**
- File-based storage
- KV-v2 secret engine
- Policy-based access control
- Audit logging
- Automatic initialization
- Automatic unseal (tek key ile)
- JSON environment variable parsing
- Backend token generation
- Docker containerization
- Volume persistence

---

## 🚧 Eksik Özellikler (Production İçin)

❌ **Yok:**
- TLS/SSL encryption
- External storage backend (Consul, etcd)
- Auto-unseal (Cloud KMS)
- High availability setup
- Multiple unseal keys (Shamir's Secret Sharing)
- Token TTL ve renewal
- Backup/restore automation
- Monitoring ve alerting
- Disaster recovery plan
- Secret rotation automation
- Network policies
- Rate limiting
- IP whitelisting

---

## 🐛 Bilinen Sınırlamalar

1. **Single Point of Failure**
   - Tek Vault instance
   - HA yok

2. **Manuel Unseal**
   - Container restart'ta unseal gerekli
   - Auto-unseal yok

3. **No Secret Rotation**
   - Secret'lar manuel güncellenmeli
   - Otomatik rotation yok

4. **No Backup**
   - File storage backup'ı manuel
   - Otomatik backup yok

5. **Development Only**
   - TLS disabled
   - Production için uygun değil

---

## 📝 Notlar

- Vault UI: `http://localhost:8200/ui`
- Login için root token kullan (`vault_keys.txt`)
- Backend token read-only, sadece `secret/env` erişimi var
- Container restart'ta unseal gerekli (auto-unseal yok)
- `.env` dosyası değiştiğinde container restart gerekli
- Audit log `/vault/logs/vault-audit.log` (JSON format)
- Token'lar `/vault/tokens/` dizininde saklanır
- Volume mount ile token'lar backend'e paylaşılır

---

**Son Güncelleme:** 17 Aralık 2025