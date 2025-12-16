-- AlterEnum
ALTER TYPE "EncryptionType" ADD VALUE 'AES256_RSA_HYBRID';

-- AlterTable
ALTER TABLE "File" ADD COLUMN "rsaEncryptedKey" TEXT;
ALTER TABLE "File" ALTER COLUMN "encryptionKey" DROP NOT NULL;
