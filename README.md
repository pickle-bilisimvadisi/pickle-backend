# Secure File Sharing Backend API

NestJS tabanlı güvenli dosya paylaşım backend API'si. Dosyaları AES-256-GCM ve RSA hibrit şifreleme ile güvenli bir şekilde depolayan ve paylaşan bir sistemdir.

## 🚀 Teknolojiler

- **NestJS** - Progressive Node.js framework
- **Prisma ORM** - PostgreSQL veritabanı yönetimi
- **JWT** - Authentication ve authorization
- **HashiCorp Vault** - Güvenli secret yönetimi
- **Cloudflare R2** - Dosya depolama (S3 compatible)
- **Docker & Docker Compose** - Konteynerizasyon
- **bcrypt** - Şifre hashleme
- **Nodemailer** - Email gönderimi

## 🔒 Güvenlik Özellikleri

- **Hibrit Şifreleme**: AES-256-GCM + RSA-2048
- **JWT Token Authentication**: Access token ve refresh token desteği
- **Email Verification**: OTP tabanlı email doğrulama
- **Rate Limiting**: Throttler ile istek sınırlama
- **Helmet.js**: HTTP güvenlik başlıkları
- **Vault Integration**: Hassas verilerin güvenli saklanması

## 📋 API Route'lar

### Authentication (`/auth`)

#### `POST /auth/register`
Yeni kullanıcı kaydı başlatır ve email'e doğrulama OTP gönderir.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Validasyonlar:**
- Email: Geçerli email formatı
- Password: En az 6 karakter, en az 1 büyük harf, 1 küçük harf, 1 rakam

**Response:**
```json
{
  "status": "success",
  "data": {
    "email": "user@example.com",
    "message": "Registration initiated. Please verify your email with the OTP sent to complete registration.",
    "emailSent": true,
    "isVerified": false
  }
}
```

---

#### `POST /auth/login`
Kayıtlı kullanıcı girişi yapar ve JWT token'ları döndürür.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "email": "user@example.com",
    "fullName": "John Doe",
    "isVerified": true,
    "isAdmin": false
  }
}
```

**Not:** Refresh token HttpOnly cookie olarak set edilir.

---

#### `POST /auth/verify-email`
Email doğrulama OTP'sini kontrol eder ve hesabı aktif hale getirir.

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "Email verified successfully",
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "email": "user@example.com",
    "isVerified": true
  }
}
```

---

#### `POST /auth/resend-verify-email-otp`
Email doğrulama OTP'sini yeniden gönderir.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "Verification OTP has been sent to your email"
  }
}
```

---

#### `POST /auth/forgot-password`
Şifre sıfırlama için email'e OTP gönderir.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "One time password has been sent to your email"
  }
}
```

---

#### `POST /auth/verify-otp`
Şifre sıfırlama OTP'sini doğrular.

**Request Body:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "One time password verified successfully"
  }
}
```

---

#### `POST /auth/reset-password`
Yeni şifre belirler (OTP doğrulandıktan sonra).

**Request Body:**
```json
{
  "email": "user@example.com",
  "new_password": "NewSecurePass123"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "Password reset successfully"
  }
}
```

---

#### `POST /auth/resend-forgot-password-otp`
Şifre sıfırlama OTP'sini yeniden gönderir.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

---

#### `GET /auth/profile`
🔐 **Auth Required** - Giriş yapmış kullanıcının profil bilgilerini döndürür.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "role": "USER",
    "isVerified": true,
    "createdAt": "2025-12-17T10:00:00.000Z"
  }
}
```

---

#### `POST /auth/refresh`
Access token'ı yeniler.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "email": "user@example.com"
  }
}
```

---

#### `POST /auth/logout`
Çıkış yapar ve refresh token'ı geçersiz kılar.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "Logged out successfully"
  }
}
```

---

### User Management (`/user`)

#### `GET /user/me`
🔐 **Auth Required** - Kendi profil bilgilerini getirir.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "password": "hashed_password",
    "role": "USER"
  }
}
```

---

#### `GET /user`
🔐 **Auth Required** | 👑 **Admin Only** - Tüm kullanıcıları listeler.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": "uuid",
      "email": "user1@example.com"
    },
    {
      "id": "uuid",
      "email": "user2@example.com"
    }
  ]
}
```

---

#### `GET /user/:id`
🔐 **Auth Required** | 👑 **Admin Only** - Belirli bir kullanıcının bilgilerini getirir.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "password": "hashed_password",
    "role": "USER"
  }
}
```

---

#### `PATCH /user/:id`
🔐 **Auth Required** - Kendi kullanıcı bilgilerini günceller.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "password": "NewPassword123"
}
```

---

#### `DELETE /user/:id`
🔐 **Auth Required** | 👑 **Admin Only** - Belirli bir kullanıcıyı siler.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "reason": "User requested account deletion"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "User deleted successfully"
  }
}
```

---

#### `DELETE /user`
🔐 **Auth Required** - Kendi hesabını siler.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "reason": "I want to delete my account"
}
```

---

### File Upload & Management (`/file`)

#### `POST /file/upload`
🔐 **Auth Required** - Tek dosya yükler (AES-256-GCM + RSA şifreleme ile).

**Headers:**
```
Authorization: Bearer {access_token}
Content-Type: multipart/form-data
```

**Form Data:**
- `file`: Dosya (max 25MB)
- `relativePath` (optional): İç dizin yolu

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "uuid",
    "fileName": "document.pdf",
    "fileLink": "https://r2.example.com/uploads/user-id/uuid-document.pdf"
  }
}
```

**Güvenlik:**
- Dosya AES-256-GCM ile şifrelenir
- AES key RSA-2048 ile şifrelenir
- Şifreli dosya Cloudflare R2'ye yüklenir
- IV, AuthTag ve şifreli key veritabanında saklanır

---

#### `POST /file/upload-folder`
🔐 **Auth Required** - Çoklu dosya/klasör yükler (max 100 dosya).

**Headers:**
```
Authorization: Bearer {access_token}
Content-Type: multipart/form-data
```

**Form Data:**
- `files`: Dosyalar (max 100)
- `paths`: JSON string array (her dosya için relative path)

**Response:**
```json
{
  "status": "success",
  "data": {
    "success": true,
    "uploaded": [
      {
        "id": "uuid1",
        "fileName": "folder/file1.txt",
        "fileLink": "https://..."
      },
      {
        "id": "uuid2",
        "fileName": "folder/file2.txt",
        "fileLink": "https://..."
      }
    ],
    "failed": [],
    "total": 2,
    "successful": 2,
    "failedCount": 0,
    "downloadToken": {
      "token": "uuid-token",
      "expiresAt": "2025-12-18T10:00:00.000Z",
      "fileIds": ["uuid1", "uuid2"]
    }
  }
}
```

**Not:** Folder upload'ta tüm dosyalar için tek bir download token oluşturulur. Bu token ile tüm dosyalar ZIP olarak indirilebilir.

---

#### `GET /file/my-files`
🔐 **Auth Required** - Kullanıcının yüklediği tüm dosyaları listeler.

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": "uuid",
      "fileName": "document.pdf",
      "fileLink": "https://r2.example.com/...",
      "downloadCount": 3,
      "maxDownloads": 1,
      "createdAt": "2025-12-17T10:00:00.000Z",
      "expiresAt": null,
      "recentDownloads": [
        {
          "id": "uuid",
          "createdAt": "2025-12-17T11:00:00.000Z",
          "ipAddress": "192.168.1.1",
          "user": {
            "id": "uuid",
            "email": "downloader@example.com"
          }
        }
      ],
      "totalDownloads": 3
    }
  ]
}
```

---

#### `GET /file/:id`
Dosya meta verilerini getirir (public endpoint).

**Response:**
```json
{
  "status": "success",
  "data": {
    "id": "uuid",
    "fileName": "document.pdf",
    "fileLink": "https://...",
    "downloadCount": 5,
    "maxDownloads": 1,
    "createdAt": "2025-12-17T10:00:00.000Z",
    "expiresAt": null
  }
}
```

---

#### `POST /file/:id/download-link`
🔐 **Auth Required** - İndirme token'ı oluşturur (tek kullanımlık link).

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "token": "uuid-token",
    "downloadUrl": "https://r2.example.com/...",
    "expiresAt": "2025-12-18T10:00:00.000Z"
  }
}
```

**Not:** Token 24 saat geçerlidir ve tek kullanımlıktır.

---

#### `GET /file/download/:token`
Token ile dosyayı indirir (şifreyi çözer ve dosyayı gönderir).

**Response (Tek Dosya):**
- Content-Type: application/octet-stream
- Content-Disposition: attachment
- Binary file data (decrypted)

**Response (Folder - Çoklu Dosya):**
- Content-Type: application/zip
- Content-Disposition: attachment; filename="folder-name.zip"
- X-File-Type: zip-collection
- ZIP file data (all files decrypted and compressed)

**İşlem Akışı:**

**Tek Dosya:**
1. Token'ı doğrula (geçerlilik, kullanım durumu, süre)
2. R2'den şifreli dosyayı indir
3. RSA ile AES key'i çöz
4. AES-256-GCM ile dosyayı çöz
5. Çözülmüş dosyayı kullanıcıya gönder
6. Download kaydı oluştur
7. Token'ı kullanılmış olarak işaretle

**Folder (Çoklu Dosya):**
1. Token'ı doğrula
2. Aynı zamanda yüklenen ilişkili dosyaları bul (±5 saniye)
3. Her dosya için:
   - R2'den şifreli dosyayı indir
   - RSA ile AES key'i çöz
   - AES-256-GCM ile dosyayı çöz
   - Download kaydı oluştur
4. Tüm dosyaları ZIP olarak paketle
5. ZIP'i kullanıcıya gönder
6. Token'ı kullanılmış olarak işaretle

---

### Root (`/`)

#### `GET /`
API health check endpoint.

**Response:**
```json
{
  "status": "success",
  "data": {
    "message": "Hello World!"
  }
}
```

---

## 🗄️ Veritabanı Yapısı

### User
- `id`: UUID (Primary Key)
- `email`: String (Unique)
- `password`: String (bcrypt hashed)
- `role`: Enum (USER, ADMIN)
- `isVerified`: Boolean
- `verifyToken`: String (OTP hash)
- `pendingEmail`: String
- `tempEmail`: String
- `otpCode`: String
- `otpExpiry`: DateTime
- `createdAt`: DateTime

### File
- `id`: UUID (Primary Key)
- `ownerId`: UUID (Foreign Key → User)
- `fileName`: String
- `fileLink`: String (R2 URL)
- `encryptionKey`: String (Deprecated)
- `rsaEncryptedKey`: String (RSA encrypted AES key)
- `iv`: String (Base64 encoded)
- `authTag`: String (Base64 encoded)
- `expiresAt`: DateTime (Optional)
- `maxDownloads`: Integer (Default: 1)
- `downloadCount`: Integer (Default: 0)
- `createdAt`: DateTime

### Download
- `id`: UUID (Primary Key)
- `fileId`: UUID (Foreign Key → File)
- `userId`: UUID (Foreign Key → User, Optional)
- `ipAddress`: String
- `createdAt`: DateTime

### DownloadToken
- `id`: UUID (Primary Key)
- `fileId`: UUID (Foreign Key → File)
- `token`: UUID (Unique)
- `used`: Boolean (Default: false)
- `expiresAt`: DateTime
- `createdAt`: DateTime

### RefreshToken
- `id`: UUID (Primary Key)
- `token`: String (Unique)
- `userId`: UUID (Foreign Key → User)
- `expiresAt`: DateTime
- `createdAt`: DateTime

---

## 🔐 Şifreleme Mimarisi

### Hibrit Şifreleme (AES + RSA)

1. **Dosya Yükleme:**
   - Random 32-byte AES key oluşturulur
   - Random 12-byte IV oluşturulur
   - Dosya AES-256-GCM ile şifrelenir
   - AES key RSA-2048 public key ile şifrelenir
   - Şifreli dosya R2'ye yüklenir
   - RSA şifreli key, IV ve AuthTag veritabanına kaydedilir

2. **Dosya İndirme:**
   - R2'den şifreli dosya indirilir
   - RSA private key ile AES key çözülür
   - IV ve AuthTag veritabanından alınır
   - AES-256-GCM ile dosya çözülür
   - Orijinal dosya kullanıcıya gönderilir

**Avantajlar:**
- RSA ile key güvenliği (public/private key cryptography)
- AES ile hızlı ve güvenli dosya şifreleme
- Veritabanında bile şifreli key (RSA encrypted)
- GCM mode ile integrity kontrolü (AuthTag)

---

## 📧 Email Servisi

### Desteklenen Email Tipleri:

1. **Verification OTP** - Kayıt doğrulama
2. **Forgot Password OTP** - Şifre sıfırlama
3. **Change Email OTP** - Email değiştirme

### Konfigürasyon (Vault):
- `EMAIL_HOST`: SMTP server
- `EMAIL_PORT`: SMTP port
- `EMAIL_USER`: SMTP username
- `EMAIL_PASSWORD`: SMTP password

---

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Docker & Docker Compose
- Node.js 24+ (development için)

### Environment Variables (.env)

```bash
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/dbname?schema=public"

# JWT
JWT_SECRET="your-secret-key"
JWT_EXPIRATION_TIME="15m"
JWT_REFRESH_SECRET="your-refresh-secret"
JWT_REFRESH_EXPIRATION_TIME="7d"

# Email (SMTP)
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT="587"
EMAIL_USER="your-email@gmail.com"
EMAIL_PASSWORD="your-app-password"

# Cloudflare R2
R2_ACCESS_KEY="your-access-key"
R2_SECRET_ACCESS_KEY="your-secret-key"
R2_ACCOUNT_ID="your-account-id"
R2_BUCKET_NAME="your-bucket"
R2_ENDPOINT="https://account-id.r2.cloudflarestorage.com"
R2_PUBLIC_BASE_URL="https://your-domain.com"

# RSA Keys (optional - auto-generated if not provided)
RSA_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
RSA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."

# CORS
ALLOWED_ORIGINS="http://localhost:3000,https://yourdomain.com"

# Server
PORT=8080
```

### Docker ile Çalıştırma

```bash
# Servisleri başlat
docker-compose up -d

# Logları izle
docker-compose logs -f

# Servisleri durdur
docker-compose down

# Veritabanı dahil tüm verileri sil
docker-compose down -v
```

### Development

```bash
# Bağımlılıkları yükle
npm install

# Prisma client oluştur
npx prisma generate

# Veritabanı migration
npx prisma migrate dev

# Development modunda başlat
npm run start:dev

# Production build
npm run build
npm run start:prod
```

---

## 📁 Proje Yapısı

```
src/
├── auth/              # Authentication & authorization
│   ├── dto/          # Data transfer objects
│   ├── guards/       # JWT ve Admin guard'ları
│   └── strategies/   # Passport JWT stratejileri
├── common/           # Ortak modüller
│   ├── filters/      # Exception filter'lar
│   └── interceptors/ # Response interceptor
├── fileupload/       # Dosya yükleme ve yönetimi
├── mail/            # Email servisi
├── prisma/          # Prisma ORM servisi
├── s3/              # S3 (R2) servisi
└── user/            # Kullanıcı yönetimi

prisma/
├── migrations/      # Veritabanı migration'ları
└── schema.prisma    # Prisma schema tanımı

vault/              # HashiCorp Vault konfigürasyonu
postgres/           # PostgreSQL Docker konfigürasyonu
```

---

## 🔒 Güvenlik Notları

1. **Şifre Politikası:**
   - En az 6 karakter
   - En az 1 büyük harf (A-Z)
   - En az 1 küçük harf (a-z)
   - En az 1 rakam (0-9)

2. **Rate Limiting:**
   - Varsayılan: 10 istek / dakika
   - Tüm endpoint'lere uygulanır

3. **Token Süresi:**
   - Access Token: 15 dakika
   - Refresh Token: 7 gün
   - OTP: 5 dakika
   - Download Token: 24 saat

4. **Dosya Limitleri:**
   - Maksimum dosya boyutu: 25MB
   - Maksimum dosya sayısı (folder upload): 100

---

## 📝 Lisans

UNLICENSED - Private project

---

## 👨‍💻 Geliştirici Notları

### Önemli Bilgiler:

- **Vault Integration**: Tüm hassas environment variable'lar Vault'ta saklanır
- **RSA Key Generation**: RSA key'ler yoksa runtime'da otomatik oluşturulur (production'da önerilmez)
- **Download Token**: Tek kullanımlık ve süreli, kullanıldıktan sonra geçersiz olur
- **File Encryption**: Her dosya için unique AES key ve IV kullanılır
- **Email Queue**: Email gönderimi async olarak çalışır, hata alınsa bile istek engellenmez

### Test Endpoints:

```bash
# Health check
curl http://localhost:8080

# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123"}'

# Upload file
curl -X POST http://localhost:8080/file/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@/path/to/file.pdf"
```

---

## 🐛 Bilinen Sorunlar

- [ ] Email servisinde SMTP timeout durumlarında retry mekanizması yok
- [ ] Büyük dosyalar için streaming upload implementasyonu yok
- [ ] File deletion endpoint'i henüz implemente edilmedi
- [ ] Admin panel için endpoint'ler eksik

---

## 🔮 Gelecek Özellikler

- [ ] WebSocket ile real-time upload progress
- [ ] Dosya önizleme desteği
- [x] ~~Çoklu dosya indirme (ZIP)~~ ✅ Eklendi
- [ ] Dosya paylaşım linki analitikleri
- [ ] Two-factor authentication (2FA)
- [ ] API rate limiting per-user
- [ ] File versioning
- [ ] Automated file expiration cleanup
- [ ] Folder structure metadata storage

---

**Son Güncelleme:** 17 Aralık 2025
