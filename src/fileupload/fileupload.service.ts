import { Injectable, BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { S3Service } from '../s3/s3.service';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
  publicEncrypt,
  privateDecrypt,
  generateKeyPairSync,
  constants,
} from 'crypto';
import { File } from 'multer';

@Injectable()
export class FileuploadService {
  private readonly publicBaseUrl: string;
  private readonly rsaPublicKey: string;
  private readonly rsaPrivateKey: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly s3Service: S3Service,
  ) {
    this.publicBaseUrl = this.configService.get<string>('R2_PUBLIC_BASE_URL');
    
    // RSA key pair'i environment variable'dan oku veya generate et
    this.rsaPublicKey = this.configService.get<string>('RSA_PUBLIC_KEY') || '';
    this.rsaPrivateKey = this.configService.get<string>('RSA_PRIVATE_KEY') || '';

    // Eğer key'ler yoksa, generate et (production için environment variable kullanılmalı)
    if (!this.rsaPublicKey || !this.rsaPrivateKey) {
      const keyPair = this.generateRSAKeyPair();
      this.rsaPublicKey = keyPair.publicKey;
      this.rsaPrivateKey = keyPair.privateKey;
      console.warn('⚠️  RSA keys generated at runtime. For production, set RSA_PUBLIC_KEY and RSA_PRIVATE_KEY environment variables.');
    }
  }

  private generateRSAKeyPair(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { publicKey, privateKey };
  }

  private encryptAESKeyWithRSA(aesKey: Buffer): string {
    if (!this.rsaPublicKey) {
      throw new BadRequestException('RSA public key bulunamadı.');
    }

    // RSA public key ile AES key'i şifrele
    const encrypted = publicEncrypt(
      {
        key: this.rsaPublicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      aesKey,
    );

    return encrypted.toString('base64');
  }

  private decryptAESKeyWithRSA(encryptedAESKey: string): Buffer {
    if (!this.rsaPrivateKey) {
      throw new BadRequestException('RSA private key bulunamadı.');
    }

    const encryptedBuffer = Buffer.from(encryptedAESKey, 'base64');

    // RSA private key ile AES key'i decrypt et
    const decrypted = privateDecrypt(
      {
        key: this.rsaPrivateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedBuffer,
    );

    return decrypted;
  }

  async uploadEncrypted(file: File, ownerId: string, relativePath?: string) {
    try {
      if (!file?.buffer) {
        throw new BadRequestException('Dosya yüklenmedi.');
      }

      const aesKey = randomBytes(32);
      const iv = randomBytes(12);

      // AES-256-GCM ile dosyayı şifrele
      const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
      const encryptedBuffer = Buffer.concat([
        cipher.update(file.buffer),
        cipher.final(),
      ]);
      const authTag = cipher.getAuthTag();

      const normalizedPath = relativePath
        ? relativePath.replace(/^\/+/, '').replace(/\\/g, '/')
        : '';

      const pathPrefix = normalizedPath ? `${normalizedPath}/` : '';
      const objectKey = `uploads/${ownerId}/${pathPrefix}${randomUUID()}-${file.originalname}`;

      await this.s3Service.uploadBuffer(
        objectKey,
        encryptedBuffer,
        'application/octet-stream',
      );

      const fileLink = `${this.publicBaseUrl}/${objectKey}`.replace(/([^:]\/)\/+/g, '$1');

      const fileName = normalizedPath ? `${normalizedPath}/${file.originalname}` : file.originalname;

      // AES key'i RSA ile şifrele (her zaman hybrid encryption kullanılıyor)
      const rsaEncryptedKey = this.encryptAESKeyWithRSA(aesKey);

      const record = await this.prisma.file.create({
        data: {
          ownerId,
          fileName,
          fileLink,
          rsaEncryptedKey,
          iv: iv.toString('base64'),
          authTag: authTag.toString('base64'),
        },
      });

      return {
        id: record.id,
        fileName: record.fileName,
        fileLink: record.fileLink,
      };
    } catch (error) {
      console.error('File upload error:', error);
      throw new BadRequestException(
        `Dosya yükleme başarısız: ${error.message}`,
      );
    }
  }

  async uploadMultipleEncrypted(
    filesWithPaths: Array<{ file: File; relativePath: string }>,
    ownerId: string,
  ) {
    const results = [];
    const errors = [];

    const uploadPromises = filesWithPaths.map(async ({ file, relativePath }) => {
      try {
        const result = await this.uploadEncrypted(file, ownerId, relativePath);
        return { success: true, result };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          fileName: file.originalname,
          relativePath,
        };
      }
    });

    const uploadResults = await Promise.all(uploadPromises);

    uploadResults.forEach((result) => {
      if (result.success) {
        results.push(result.result);
      } else {
        errors.push({
          fileName: result.fileName,
          relativePath: result.relativePath,
          error: result.error,
        });
      }
    });

    return {
      success: errors.length === 0,
      uploaded: results,
      failed: errors,
      total: filesWithPaths.length,
      successful: results.length,
      failedCount: errors.length,
    };
  }

  async getFileById(fileId: string) {
    const file = await this.prisma.file.findUnique({
      where: { id: fileId },
      select: {
        id: true,
        fileName: true,
        fileLink: true,
        downloadCount: true,
        maxDownloads: true,
        createdAt: true,
        expiresAt: true,
      },
    });

    if (!file) {
      throw new NotFoundException('Dosya bulunamadı.');
    }

    return {
      id: file.id,
      fileName: file.fileName,
      fileLink: file.fileLink,
      downloadCount: file.downloadCount,
      maxDownloads: file.maxDownloads,
      createdAt: file.createdAt,
      expiresAt: file.expiresAt,
    };
  }

  async getUserFiles(userId: string) {
    const files = await this.prisma.file.findMany({
      where: {
        ownerId: userId,
      },
      select: {
        id: true,
        fileName: true,
        fileLink: true,
        downloadCount: true,
        maxDownloads: true,
        createdAt: true,
        expiresAt: true,
        downloads: {
          select: {
            id: true,
            createdAt: true,
            ipAddress: true,
            user: {
              select: {
                id: true,
                email: true,
              },
            },
          },
          orderBy: {
            createdAt: 'desc',
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return files.map((file) => ({
      id: file.id,
      fileName: file.fileName,
      fileLink: file.fileLink,
      downloadCount: file.downloadCount,
      maxDownloads: file.maxDownloads,
      createdAt: file.createdAt,
      expiresAt: file.expiresAt,
      recentDownloads: file.downloads.slice(0, 10),
      totalDownloads: file.downloads.length,
    }));
  }

  async generateDownloadToken(fileId: string, userId: string) {
    const file = await this.prisma.file.findFirst({
      where: {
        id: fileId,
        ownerId: userId,
      },
    });

    if (!file) {
      throw new NotFoundException('Dosya bulunamadı veya size ait değil.');
    }

    const token = randomUUID();

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    const downloadToken = await this.prisma.downloadToken.create({
      data: {
        fileId: file.id,
        token,
        expiresAt,
      },
    });

    return {
      token: downloadToken.token,
      downloadUrl: file.fileLink,
      expiresAt: downloadToken.expiresAt,
    };
  }

  async downloadFileWithToken(token: string, userId?: string, ipAddress?: string) {
    const downloadToken = await this.prisma.downloadToken.findUnique({
      where: { token },
      include: {
        file: {
          include: {
            owner: true,
          },
        },
      },
    });

    if (!downloadToken) {
      throw new NotFoundException('Geçersiz indirme linki.');
    }

    if (downloadToken.used) {
      throw new ForbiddenException('Bu indirme linki zaten kullanılmış.');
    }

    if (new Date() > downloadToken.expiresAt) {
      throw new ForbiddenException('Bu indirme linkinin süresi dolmuş.');
    }

    await this.prisma.downloadToken.update({
      where: { id: downloadToken.id },
      data: { used: true },
    });

    await this.prisma.file.update({
      where: { id: downloadToken.fileId },
      data: {
        downloadCount: {
          increment: 1,
        },
      },
    });

    await this.prisma.download.create({
      data: {
        fileId: downloadToken.fileId,
        userId: userId || null,
        ipAddress: ipAddress || null,
      },
    });

    const file = downloadToken.file;
    const objectKey = file.fileLink.replace(this.publicBaseUrl + '/', '').replace(/^\/+/, '');

    const encryptedBuffer = await this.s3Service.downloadBuffer(objectKey);

    const iv = Buffer.from(file.iv, 'base64');
    const authTag = Buffer.from(file.authTag, 'base64');

    // RSA ile AES key'i decrypt et (her zaman hybrid encryption kullanılıyor)
    if (!file.rsaEncryptedKey) {
      throw new BadRequestException('RSA şifreli key bulunamadı. Dosya hybrid encryption ile şifrelenmemiş.');
    }

    let aesKey: Buffer;
    try {
      aesKey = this.decryptAESKeyWithRSA(file.rsaEncryptedKey);
    } catch (error) {
      console.error('RSA decryption error:', error);
      throw new BadRequestException('AES key decrypt edilemedi.');
    }

    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);

    const decryptedBuffer = Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final(),
    ]);

    return {
      buffer: decryptedBuffer,
      fileName: file.fileName,
      contentType: 'application/octet-stream',
    };
  }
}

