/*
  Warnings:

  - The primary key for the `Download` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `File` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `encryptionType` on the `File` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "Download" DROP CONSTRAINT "Download_fileId_fkey";

-- DropForeignKey
ALTER TABLE "DownloadToken" DROP CONSTRAINT "DownloadToken_fileId_fkey";

-- AlterTable
ALTER TABLE "Download" DROP CONSTRAINT "Download_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "fileId" SET DATA TYPE TEXT,
ADD CONSTRAINT "Download_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Download_id_seq";

-- AlterTable
ALTER TABLE "DownloadToken" ALTER COLUMN "fileId" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "File" DROP CONSTRAINT "File_pkey",
DROP COLUMN "encryptionType",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ADD CONSTRAINT "File_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "File_id_seq";

-- DropEnum
DROP TYPE "EncryptionType";

-- AddForeignKey
ALTER TABLE "Download" ADD CONSTRAINT "Download_fileId_fkey" FOREIGN KEY ("fileId") REFERENCES "File"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DownloadToken" ADD CONSTRAINT "DownloadToken_fileId_fkey" FOREIGN KEY ("fileId") REFERENCES "File"("id") ON DELETE CASCADE ON UPDATE CASCADE;
